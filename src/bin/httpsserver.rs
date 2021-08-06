use bytes::Bytes;
use tokio::io::AsyncReadExt;

use nsfu::ReadablePacketFragment;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443").await?;

    while let Ok((mut socket, _addr)) = listener.accept().await {
        let mut buffer = Vec::new();
        socket.read_to_end(&mut buffer).await?;

        let mut buffer: Bytes = buffer.into();

        let mut context = nsfu::Context::default();
        let client_hello = nsfu::Record::read(
            &mut buffer,
            &mut context,
        )?;

        println!("{:#?}", client_hello);
    }

    Ok(())
}

