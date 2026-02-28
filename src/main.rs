use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use chrono::Utc;
use axum::{Router, routing::get, Json, extract::State};
use serde::Serialize;
use sqlx::Row;
use tower_http::cors::{CorsLayer, Any};
use axum::http::Method;
use maxminddb::{Reader, geoip2};
use std::net::IpAddr;
use tokio::sync::broadcast;
use axum::extract::ws::{WebSocketUpgrade, WebSocket, Message};
use axum::response::IntoResponse;
use axum::http::HeaderMap;
use tower_http::services::ServeDir;
use tokio::time::{interval, Duration};
use std::sync::Arc;

#[derive(Serialize)]
struct Log {
    id: i64,
    ip: String,
    input: String,
    timestamp: String,
}

#[derive(Serialize)]
struct IpRanking {
    ip: String,
    count: i64,
}

#[derive(Serialize)]
struct HourlyStat {
    hour: String,
    count: i64,
}

#[derive(Serialize)]
struct BruteforceStat {
    ip: String,
    attempts: i64,
    window_minutes: i64,
}

#[derive(Serialize)]
struct CountryStat {
    country: String,
    count: i64,
}

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    tx: broadcast::Sender<String>,
    geo_reader: std::sync::Arc<Reader<Vec<u8>>>,
}

#[derive(Serialize)]
struct AttackEvent {
    event_type: String,
    ip: String,
    country: String,
    lat: f64,
    lon: f64,
    timestamp: String,
}

#[derive(Serialize)]
struct GeoInfo {
    country: String,
    lat: f64,
    lon: f64,
}

fn lookup_geo(ip: &str, reader: &Reader<Vec<u8>>) -> Option<GeoInfo> {
    let ip_addr: IpAddr = ip.parse().ok()?;
    let city: geoip2::City = reader.lookup(ip_addr).ok()?;

    let country = city
        .country?
        .names?
        .get("en")?
        .to_string();

    let location = city.location?;

    Some(GeoInfo {
        country,
        lat: location.latitude?,
        lon: location.longitude?,
    })
}

fn lookup_country(ip: &str, reader: &Reader<Vec<u8>>) -> Option<String> {
    let ip_addr: IpAddr = ip.parse().ok()?;
    let country: geoip2::Country = reader.lookup(ip_addr).ok()?;
    country
        .country?
        .names?
        .get("en")
        .map(|name| name.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let geo_reader = Arc::new(
        Reader::open_readfile("GeoLite2-City.mmdb")?
    );

    // DB接続
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:///home/honeypot/honeypot.db")
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            input TEXT,
            timestamp TEXT NOT NULL
        )
        "#
    )
    .execute(&pool)
    .await?;

    let (tx, _) = broadcast::channel(100);
    let state = AppState {
        pool: pool.clone(),
        tx: tx.clone(),
        geo_reader: geo_reader.clone(),
    };

    let app_state = state.clone();
    let honeypot_state = state.clone();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET])
        .allow_headers(Any);

    // Web-API
    let app = Router::new()
        .route("/logs", get(get_logs))
        .route("/stats/ip-ranking", get(get_ip_ranking))
        .route("/stats/hourly", get(get_hourly_stats))
        .route("/stats/bruteforce", get(get_bruteforce_stats))
        .route("/stats/countries", get(get_country_stats))
        .route("/ws", get(ws_handler))
        .nest_service("/", ServeDir::new("/home/honeypot/dist"))
        .layer(cors)
        .with_state(app_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    let web_server = axum::serve(listener, app);

    // Honeypot TCP
    let honeypot = async move {
        let listener = TcpListener::bind("0.0.0.0:2222").await?;
        println!("Honeypot running on port 2222");

        loop {
            let (mut socket, addr) = listener.accept().await?;
            let pool = honeypot_state.pool.clone();
            let tx = honeypot_state.tx.clone();
            let geo_reader = honeypot_state.geo_reader.clone();

            tokio::spawn(async move {
                let mut buffer = [0; 1024];

                let _ = socket.write_all(b"SSH-2.0-OpenSSH_8.2p1\r\nlogin: ").await;

                loop {
                    let n = match socket.read(&mut buffer).await {
                        Ok(n) if n == 0 => return,
                        Ok(n) => n,
                        Err(_) => return,
                     };

                let input = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                let timestamp = Utc::now().to_rfc3339();

                let _ = sqlx::query(
                    "INSERT INTO attack_logs (ip, input, timestamp) VALUES (?, ?, ?)"
                )
                    .bind(addr.to_string())
                    .bind(input.clone())
                    .bind(&timestamp)
                    .execute(&pool)
                    .await;

                let _ = sqlx::query(
                    "DELETE FROM attack_logs WHERE id < (SELECT MAX(id) - 100000 FROM attack_logs)"
                )
                    .execute(&pool)
                    .await;

                let ip_only = addr.to_string().split(':').next().unwrap().to_string();

                if let Some(geo) = lookup_geo(&ip_only, &geo_reader) {
                    let event = AttackEvent {
                        event_type: "attack".to_string(),
                        ip: addr.to_string(),
                        country: geo.country,
                        lat: geo.lat,
                        lon: geo.lon,
                        timestamp: timestamp.clone(),
                    };

                    if let Ok(json) = serde_json::to_string(&event) {
                        let _ = tx.send(json);
                    }
                }

                let _ = socket.write_all(b"Permission denied\r\nlogin: ").await;
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error>>(())
    };

    println!("Web API running on http://127.0.0.1:3000/logs");

    tokio::join!(web_server, honeypot);

    Ok(())
}

async fn get_logs(
    State(state): State<AppState>,
) -> Json<Vec<Log>> {

    let rows = sqlx::query(
        r#"
        SELECT id, ip, input, timestamp
        FROM attack_logs
        ORDER BY id DESC
        LIMIT 100
        "#
    )
    .fetch_all(&state.pool)
    .await
    .unwrap();

    let logs = rows
        .into_iter()
        .map(|row| Log {
            id: row.get("id"),
            ip: row.get("ip"),
            input: row.get("input"),
            timestamp: row.get("timestamp"),
        })
        .collect();

    Json(logs)
}

async fn get_ip_ranking(
    State(state): State<AppState>,
) -> Json<Vec<IpRanking>> {
    let rows = sqlx::query(
        r#"
        SELECT ip, count(*) as count
        FROM attack_logs
        GROUP BY ip
        ORDER BY count DESC
        LIMIT 20
        "#
    )
    .fetch_all(&state.pool)
    .await
    .unwrap();

    let ranking = rows
        .into_iter()
        .map(|row| IpRanking {
            ip: row.get("ip"),
            count: row.get("count"),
        })
        .collect();

    Json(ranking)
}

async fn get_hourly_stats(
    State(state): State<AppState>,
) -> Json<Vec<HourlyStat>> {
    let rows = sqlx::query(
        r#"
        SELECT
            strftime('%Y-%m-%dT%H:00', timestamp) as hour,
            COUNT(*) as count
        FROM attack_logs
        GROUP BY hour
        ORDER BY hour ASC
        "#
    )
    .fetch_all(&state.pool)
    .await
    .unwrap();

    let stats = rows
        .into_iter()
        .map(|row| HourlyStat {
            hour: row.get("hour"),
            count: row.get("count"),
        })
        .collect();

    Json(stats)
}

async fn get_bruteforce_stats(
    State(state): State<AppState>,
) -> Json<Vec<BruteforceStat>> {
    let rows = sqlx::query(
        r#"
        SELECT ip, COUNT(*) as attempts
        FROM attack_logs
        WHERE timestamp >= datetime('now', '-5 minutes')
        GROUP BY ip
        HAVING attempts >= 10
        ORDER BY attempts DESC
        "#
    )
    .fetch_all(&state.pool)
    .await
    .unwrap();

    let stats = rows
        .into_iter()
        .map(|row| BruteforceStat {
            ip: row.get("ip"),
            attempts: row.get("attempts"),
            window_minutes: 5,
        })
        .collect();

    Json(stats)
}

async fn get_country_stats(
    State(state): State<AppState>,
) -> Json<Vec<CountryStat>> {
    let rows = sqlx::query(
        r#"
        SELECT ip, COUNT(*) as count
        FROM attack_logs
        GROUP BY ip
        "#
    )
    .fetch_all(&state.pool)
    .await
    .unwrap();

    let reader = &state.geo_reader;

    let mut map = std::collections::HashMap::new();

    for row in rows {
        let ip: String = row.get("ip");
        let count: i64 = row.get("count");

        if let Some(country_name) = lookup_country(ip.split(':').next().unwrap(), reader) {
            *map.entry(country_name).or_insert(0) += count;
        }
    }

    let result = map
        .into_iter()
        .map(|(country, count)| CountryStat { country, count })
        .collect();

    Json(result)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {

    println!("WS headers: {:?}", headers);

    let tx = state.tx.clone();

    ws.on_upgrade(move |socket| async move {
        let rx = tx.subscribe();
        handle_socket(socket, rx).await;
    })
}

async fn handle_socket(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<String>,
) {
    println!("WebSocket connected");

    // 最初に1回だけ送る
    let _ = socket
        .send(Message::Text(r#"{"event_type":"connected"}"#.to_string()))
        .await;

    let mut heartbeat = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Attack
            Ok(msg) = rx.recv() => {
                if socket.send(Message::Text(msg)).await.is_err() {
                    println!("WebSocket disconnected");
                    break;
                }
            }

            // HeartBeat
            _ = heartbeat.tick() => {
                let ping = r#"{"event_type":"ping"}"#;
                if socket.send(Message::Text(ping.to_string())).await.is_err() {
                    println!("WebSocket disconnected");
                    break;
                }
            }
        }
    }
}

