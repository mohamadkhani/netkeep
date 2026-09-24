//! System tray via the StatusNotifierItem (SNI) protocol.
//!
//! Uses our vendored `ksni` fork (crates/ksni) which adds the
//! `ProvideXdgActivationToken` SNI method. The GNOME AppIndicator shell
//! extension mints an xdg-activation token **inside the compositor** and
//! delivers it to us via that method immediately before activating/clicking;
//! we stash it and forward it to the GPUI window so Mutter honors the raise
//! (instead of falling back to a demand-attention notification).
//!
//! See docs/tray-window-focus-wayland.md and the
//! gnome-appindicator-provide-xdg-activation-token memory.

use std::sync::{Arc, Mutex};

use ksni::{
    menu::{MenuItem, StandardItem},
    Category, Icon, Tray,
};

/// The last compositor-provided activation token, shared between the SNI
/// service thread (which receives it) and the menu-item click handlers.
pub type SharedToken = Arc<Mutex<Option<String>>>;

/// Actions the tray requests the GPUI main loop to perform.
pub enum TrayAction {
    /// Toggle NFQUEUE interception on.
    NfqueueEnable,
    /// Toggle NFQUEUE interception off.
    NfqueueDisable,
    /// Open or raise the settings window. The optional token is the
    /// compositor-minted xdg-activation token to feed `activate_with_token`.
    Settings { token: Option<String> },
    /// Quit the whole app.
    Quit,
}

/// Netkeep's SNI tray.
pub struct LogiTray {
    /// Last token delivered by the host before a click; consumed by menu handlers.
    pub token: SharedToken,
    /// Where menu actions are sent (to the GPUI main loop).
    pub action_tx: std::sync::mpsc::Sender<TrayAction>,
    /// Whether network interception is currently enabled (drives the icon).
    pub nfqueue_enabled: bool,
}

impl LogiTray {
    pub fn new(
        action_tx: std::sync::mpsc::Sender<TrayAction>,
        token: SharedToken,
        nfqueue_enabled: bool,
    ) -> Self {
        Self {
            token,
            action_tx,
            nfqueue_enabled,
        }
    }
}

impl Tray for LogiTray {
    fn id(&self) -> String {
        "netkeep".into()
    }
    fn title(&self) -> String {
        "Netkeep".into()
    }
    fn category(&self) -> Category {
        Category::SystemServices
    }
    fn icon_name(&self) -> String {
        // Deliberately empty. GNOME's AppIndicator extension prefers
        // `IconName` over `IconPixmap` whenever the name resolves in the icon
        // theme (see appIndicator.js `_createIcon`: `if (name) { ...; if (gicon)
        // return gicon; }`). A real name like "security-high" shadows our
        // pixmap, so the color would never change. Returning "" forces the
        // extension to render our `icon_pixmap`, which is the only thing we
        // can color dynamically.
        String::new()
    }
    fn icon_pixmap(&self) -> Vec<Icon> {
        let color = if self.nfqueue_enabled {
            0x14b8a6 // teal
        } else {
            0x6b7280 // gray
        };
        vec![shield_icon(color)]
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "Netkeep".into(),
            description: if self.nfqueue_enabled {
                "Network interception enabled".into()
            } else {
                "Network interception disabled".into()
            },
            ..Default::default()
        }
    }

    fn on_activation_token(&mut self, token: String) {
        crate::diag_log(&format!(
            "tray: ProvideXdgActivationToken received ({} chars)",
            token.len()
        ));
        if let Ok(mut g) = self.token.lock() {
            *g = Some(token);
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let token = self.token.clone();
        let tx_manage = self.action_tx.clone();
        let token_for_manage = token.clone();

        let tx_enable = self.action_tx.clone();
        let tx_disable = self.action_tx.clone();
        let tx_quit = self.action_tx.clone();

        vec![
            MenuItem::Standard(StandardItem {
                label: "Enable Network Interception".into(),
                activate: Box::new(move |_this| {
                    let _ = tx_enable.send(TrayAction::NfqueueEnable);
                }),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "Disable Network Interception".into(),
                activate: Box::new(move |_this| {
                    let _ = tx_disable.send(TrayAction::NfqueueDisable);
                }),
                ..Default::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "Settings…".into(),
                activate: Box::new(move |_this| {
                    // The host delivered the token (if it supports
                    // ProvideXdgActivationToken) just before this click.
                    let token = token_for_manage.lock().ok().and_then(|mut g| g.take());
                    let _ = tx_manage.send(TrayAction::Settings { token });
                }),
                ..Default::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "Quit".into(),
                activate: Box::new(move |_this| {
                    let _ = tx_quit.send(TrayAction::Quit);
                }),
                ..Default::default()
            }),
        ]
    }
}

/// Render a clean shield-with-check security icon as ARGB32 (network byte order).
///
/// Distinct from GNOME's network indicators. The shield is filled with
/// `color_rgb` (teal when interception is on, gray when off) with a white
/// checkmark. Rendered at 4× then box-downsampled for anti-aliased edges;
/// background is transparent so it blends into any panel.
fn shield_icon(color_rgb: u32) -> Icon {
    const OUT: i32 = 64; // final icon size
    const SS: i32 = 4; // supersample factor (working resolution = OUT*SS)

    let (r0, g0, b0) = (
        ((color_rgb >> 16) & 0xff) as f32,
        ((color_rgb >> 8) & 0xff) as f32,
        (color_rgb & 0xff) as f32,
    );

    // Shield silhouette on the HI×HI canvas (classic heraldic shield).
    // Geometry: flat top with rounded corners, near-straight upper sides, a
    // smooth belly curving in to a point at the bottom.
    let in_shield = |x: f32, y: f32| -> bool {
        let cx = 128.0_f32;
        let top = 24.0_f32;
        let bottom = 236.0;
        let corner_end = 52.0; // y where rounded top corners end
        let side_end = 150.0; // y where straight sides end, belly begins
        let half_top = 100.0; // half-width across the flat top
        let corner_r = 28.0; // top-corner radius

        if y < top || y > bottom {
            return false;
        }

        if y <= corner_end {
            // Rounded top corners: at y=top the width is half_top - corner_r
            // (flat segment), widening to half_top by y=corner_end.
            let dy = y - top; // 0..corner_r
            if dy < corner_r {
                let flat_half = half_top - corner_r;
                let ax = flat_half; // distance from center to arc center
                let local_x = (x - cx).abs();
                if local_x <= ax {
                    return true; // inside the flat top segment
                }
                // quarter-circle corner: (local_x - ax)^2 + (corner_r - dy)^2 <= corner_r^2
                let dxc = local_x - ax;
                let dyc = corner_r - dy;
                return dxc * dxc + dyc * dyc <= corner_r * corner_r;
            }
            return (x - cx).abs() <= half_top;
        }

        let half_w = if y <= side_end {
            // Very slight inward taper on the upper sides.
            let t = (y - corner_end) / (side_end - corner_end);
            half_top - t * 4.0
        } else {
            // Belly: smooth curve to a point at the bottom.
            let t = (y - side_end) / (bottom - side_end); // 0..1
            let e = t * t * (3.0 - 2.0 * t); // smoothstep
            (half_top - 4.0) * (1.0 - e)
        };
        (x - cx).abs() <= half_w
    };

    // Checkmark: a thick, rounded polyline (white), centered in the shield.
    let on_check = |x: f32, y: f32| -> bool {
        let pts = [(84.0_f32, 130.0), (118.0, 164.0), (178.0, 96.0)];
        let stroke = 13.0; // half-thickness
        let mut min_d = f32::MAX;
        for w in pts.windows(2) {
            let (ax, ay) = w[0];
            let (bx, by) = w[1];
            let vx = bx - ax;
            let vy = by - ay;
            let len2 = vx * vx + vy * vy;
            let t = if len2 > 0.0 {
                ((x - ax) * vx + (y - ay) * vy) / len2
            } else {
                0.0
            };
            let t = t.clamp(0.0, 1.0);
            let px = ax + t * vx;
            let py = ay + t * vy;
            let d = ((x - px).powi(2) + (y - py).powi(2)).sqrt();
            if d < min_d {
                min_d = d;
            }
        }
        min_d <= stroke
    };

    // Render at HI resolution: count coverage over the SS×SS block per output px.
    let mut data = Vec::with_capacity((OUT * OUT * 4) as usize);
    for oy in 0..OUT {
        for ox in 0..OUT {
            let mut sh_hits = 0u32; // shield-covered supersamples
            let mut ck_hits = 0u32; // check-covered supersamples
            let mut n = 0u32;
            for sy in 0..SS {
                for sx in 0..SS {
                    let hx = (ox * SS + sx) as f32 + 0.5;
                    let hy = (oy * SS + sy) as f32 + 0.5;
                    n += 1;
                    if in_shield(hx, hy) {
                        sh_hits += 1;
                        if on_check(hx, hy) {
                            ck_hits += 1;
                        }
                    }
                }
            }
            let sh = sh_hits as f32 / n as f32; // shield alpha 0..1
            let ck_cov = if sh_hits > 0 {
                ck_hits as f32 / sh_hits as f32
            } else {
                0.0
            }; // fraction of the shield covered by the check

            let a = sh;
            // Blend toward white where the check is.
            let wr = r0 + (255.0 - r0) * ck_cov;
            let wg = g0 + (255.0 - g0) * ck_cov;
            let wb = b0 + (255.0 - b0) * ck_cov;

            data.push((a * 255.0).round() as u8);
            data.push(wr.round() as u8);
            data.push(wg.round() as u8);
            data.push(wb.round() as u8);
        }
    }
    Icon {
        width: OUT,
        height: OUT,
        data,
    }
}

/// Spawn the SNI tray service on a dedicated tokio runtime thread.
///
/// Returns the receiver for tray actions plus:
///
/// - `state_tx`: send a new NFQUEUE-enabled bool to refresh the tray icon.
/// - `stop_tx`: signal the tray service to shut down.
///
/// The thread lives until `stop_tx` is dropped or signalled.
pub fn spawn_tray(
    nfqueue_enabled: bool,
) -> (
    std::sync::mpsc::Receiver<TrayAction>,
    tokio::sync::mpsc::UnboundedSender<bool>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (action_tx, action_rx) = std::sync::mpsc::channel::<TrayAction>();
    let token: SharedToken = Arc::new(Mutex::new(None));

    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    // State updates from the GPUI loop → ksni thread (to refresh the icon).
    let (state_tx, mut state_rx) = tokio::sync::mpsc::unbounded_channel::<bool>();

    let tray = LogiTray::new(action_tx, token, nfqueue_enabled);
    std::thread::Builder::new()
        .name("ksni-tray".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime for ksni");
            runtime.block_on(async move {
                // Build + spawn the service. Keep the Handle alive (it owns the
                // background D-Bus task) until the stop signal fires.
                let handle = ksni::TrayMethods::assume_sni_available(tray, true)
                    .spawn()
                    .await;
                match handle {
                    Ok(handle) => {
                        crate::diag_log("tray: ksni service spawned");
                        // Hold the handle until stopped. Meanwhile, apply any
                        // incoming NFQUEUE-state updates so the icon refreshes.
                        loop {
                            tokio::select! {
                                biased;
                                _ = &mut stop_rx => break,
                                Some(enabled) = state_rx.recv() => {
                                    // Update the tray field and let ksni
                                    // re-emit the changed Icon/ToolTip props.
                                    handle
                                        .update(|t| { t.nfqueue_enabled = enabled })
                                        .await;
                                }
                            }
                        }
                        drop(handle);
                    }
                    Err(e) => {
                        crate::diag_log(&format!("tray: ksni spawn failed: {e}"));
                    }
                }
            });
        })
        .expect("spawn ksni thread");

    (action_rx, state_tx, stop_tx)
}
