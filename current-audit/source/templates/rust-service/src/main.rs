use axum::{routing::get,Router};async fn health()->&'static str{"ok"}#[tokio::main]async fn main(){let app=Router::new().route("/healthz",get(health));let l=tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();axum::serve(l,app).await.unwrap();}
#[cfg(test)]mod tests{#[test]fn smoke(){assert_eq!(2+3,5);}}
