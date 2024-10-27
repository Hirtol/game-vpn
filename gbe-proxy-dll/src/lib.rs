#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: windows::Win32::Foundation::HMODULE,
    fdw_reason: u32,
    lpv_reserved: *const std::ffi::c_void,
) -> i32 {
    let hinst_pointer = hinst_dll.0 as usize;

    match fdw_reason {
        windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH => {
            let _ =
                windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls(hinst_dll);

            if let Err(e) = std::panic::catch_unwind(|| {
                let hinst = windows::Win32::Foundation::HMODULE(
                    hinst_pointer as *mut core::ffi::c_void,
                );
                
                let app = gbe_proxy::dll_critical_setup(hinst).expect("DLL Critical section failed");
                std::thread::spawn(move || {
                    let hinst = windows::Win32::Foundation::HMODULE(
                        hinst_pointer as *mut core::ffi::c_void,
                    );
                    match gbe_proxy::dll_attach(hinst, app) {
                        Ok(_) => {}
                        Err(e) => eprintln!("`dll_attach` returned an Err: {:#?}", e),
                    }
                })
            }) {
                eprintln!("`dll_attach` has panicked: {:#?}", e);
            }

            true as i32
        }
        windows::Win32::System::SystemServices::DLL_PROCESS_DETACH => {
            if lpv_reserved.is_null() {
                match std::panic::catch_unwind(|| {
                    let hinst = windows::Win32::Foundation::HMODULE(
                        hinst_pointer as *mut core::ffi::c_void,
                    );
                    gbe_proxy::dll_detach(hinst)
                }) {
                    Err(e) => {
                        eprintln!("`dll_detach` has panicked: {:#?}", e);
                    }
                    Ok(r) => match r {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("`dll_detach` returned an Err: {:#?}", e);
                        }
                    },
                }
            }

            true as i32
        }
        _ => true as i32,
    }
}