#![feature(thread_id_value)]
#![recursion_limit = "256"]
use std::sync::Arc;
use arc_swap::ArcSwap;
use eyre::ContextCompat;
use crate::hooking::ClientState;
use crate::quic_conn::{DormantClientState, QuicClient};

mod hooking;
mod trace;
mod quic_conn;
mod config;
mod socket_directory;
mod queue;

pub struct Application {
    rt: tokio::runtime::Runtime,
    client: Arc<ArcSwap<ClientState>>
}

/// Executed as soon as possible
pub fn dll_critical_setup(_hinst_dll: windows::Win32::Foundation::HMODULE) -> eyre::Result<Application> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("GBE Proxy")
        .build()?;
    let handle = rt.handle().clone();

    let dormant_client = Arc::new(ArcSwap::new(Arc::new(ClientState::Dormant(Arc::new(DormantClientState::new())))));

    let manager = unsafe { hooking::ProxyManager::new(dormant_client.clone(), handle)? };

    let _ = hooking::PROXY_MAN.set(manager);

    Ok(Application {
        rt,
        client: dormant_client,
    })
}

/// Executed after `dll_critical_setup`, in a separate thread.
pub fn dll_attach(hinst_dll: windows::Win32::Foundation::HMODULE, app: Application) -> eyre::Result<()> {
    let dll_path = rust_hooking_utils::get_current_dll_path(hinst_dll)?;
    
    let config_directory = dll_path.parent().context("DLL is in root")?;
    config::create_initial_config(config_directory)?;
    
    let config = config::load_config(config_directory)?;
    if config.debug.console {
        unsafe {
            windows::Win32::System::Console::AllocConsole()?;
            let _ = ansi_term::enable_ansi_support();
        }
    }
    
    let root_dir = config.debug.file_log.then_some(dll_path.parent().context("DLL is in root")?);
    trace::create_subscriber("WARN,gbe_proxy=TRACE,gbe_proxy_common=TRACE", root_dir)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    tracing::info!("Attempting to connect to server at: {config:#?}");
    
    app.rt.block_on(async move {
        let ClientState::Dormant(dormant_state) = &**app.client.load() else {
            unreachable!("The client can't already be initialised!")
        };
        let client = QuicClient::new((config.server_address, config.server_port).into(), dormant_state.clone()).await?;
        let arc_client = Arc::new(ClientState::Ready(client));
        app.client.swap(arc_client.clone());

        arc_client.as_client().unwrap().run().await?;
        Ok(())
    })
}

pub fn dll_detach(_hinst_dll: windows::Win32::Foundation::HMODULE) -> eyre::Result<()> {
    Ok(())
}
