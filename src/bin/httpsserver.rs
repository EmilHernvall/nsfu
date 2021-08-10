use nsfu::ReadablePacketFragment;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:8443")?;

    while let Ok((mut socket, _addr)) = listener.accept() {
        let mut context = nsfu::Context::default();
        let client_hello = nsfu::Record::read(
            &mut socket,
            &mut context,
        )?;

        println!("{:#?}", client_hello);
    }

    Ok(())
}

