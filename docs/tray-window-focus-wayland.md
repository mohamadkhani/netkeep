# Tray Window Focus on GNOME/Wayland — Research & Analysis

Date: 2026-07-12

## Problem

On GNOME/Wayland, clicking "Settings…" in Netkeep's tray menu does not reliably raise and focus
the settings window. The current implementation spawns a clickable popup instead of directly
activating the existing window.

## Root Cause

GNOME/Wayland enforces **user-initiated activation** via the `xdg-activation-v1` protocol. A
process cannot raise its own window (or another process's window) without a compositor-supplied
activation token that proves the request originated from a user gesture.

Netkeep's architecture splits the tray and settings window into **separate processes**:

```
[tray process]  ── Unix socket IPC ──>  [settings process]
  owns SNI D-Bus name                     owns the window surface
  receives user click                     calls activate_window()
```

The settings process has no activation token — the compositor sees an arbitrary process trying to
steal focus and rejects it.

## Comparison with Reference Apps

### Throne (C++/Qt6)

| Aspect | Detail |
|--------|--------|
| Tray library | `QSystemTrayIcon` (renders as SNI on Wayland) |
| Process model | **Single process** — tray and window share one `QApplication` |
| Raise path | `QSystemTrayIcon::activated(Trigger)` → `ActivateWindow(w)` → `raise()` + `activateWindow()` |
| Linux-specific code | None — relies entirely on Qt's internal `xdg-activation-v1` support |
| Wayland token handling | Qt 6.5+ acquires a token from the compositor via `xdg_activation_v1` when `requestActivate()` is called within the same Wayland connection |

Key code (`src/global/Utils.cpp:293`):

```cpp
void ActivateWindow(QWidget *w) {
    w->setWindowState(w->windowState() & ~Qt::WindowMinimized);
    w->setVisible(true);
    // Linux: no special #ifdef — just raise + activateWindow
    w->raise();
    w->activateWindow();
}
```

Single-instance enforcement uses `QLocalServer`/`QLocalSocket`; when a second instance connects,
the primary raises itself via `MW_dialog_message(MwMessage::Raise, {})`.

**Why it works:** The tray menu and window are in the same process and same Wayland connection.
The compositor treats the `activate` request as user-initiated because it originates from the
same surface the user just interacted with (the tray popup). Throne does not need explicit
token passing — Qt handles it internally.

**TrayProfileSelector workaround:** Native submenus fail on SNI/DBusMenu, so Throne draws its
own `QFrame` popup (`Qt::Tool | FramelessWindowHint | WindowStaysOnTopHint`) positioned near
the tray click location, with a 150ms arming delay to avoid instant dismiss.

### Telegram Desktop (C++/Qt6)

| Aspect | Detail |
|--------|--------|
| Tray library | `QSystemTrayIcon` (SNI on Wayland, with SNI watcher for hot-reconnect) |
| Process model | **Single process** |
| Raise path | `_iconClicks` → `_minimizeMenuItemClicks` → `showFromTrayRequests()` → `Application::activate()` → `MainWindow::activate()` |
| Linux-specific code | `Platform::ActivateThisProcess()` — **complete no-op on Linux** |
| Wayland tray activation | **Broken.** No activation token is passed. GNOME flashes the dock icon but does not raise the window. |

Key code (`window/main_window.cpp:615`):

```cpp
void MainWindow::activate() {
    bool wasHidden = !isVisible();
    setWindowState(windowState() & ~Qt::WindowMinimized);
    setVisible(true);
    Platform::ActivateThisProcess();  // NO-OP on Linux
    raise();
    activateWindow();
}
```

**Notification path (works correctly):** Telegram Desktop handles activation tokens for
notification clicks via `org.freedesktop.Notifications` `ActivationToken` signal:

```cpp
// platform/linux/notifications_manager_linux.cpp
_interface.signal_activation_token().connect([=](..., uint id, std::string token) {
    GLib::setenv("XDG_ACTIVATION_TOKEN", token, true);
    // ... later, activate() reads this env var
});
```

The compositor provides a token when the user clicks a notification bubble. Qt reads
`XDG_ACTIVATION_TOKEN` in its Wayland plugin and passes it to `xdg_activation_v1`. This
works. The tray path never sets this token.

## Comparison Table

| | Throne | Telegram Desktop | Netkeep (before fix) | Netkeep (after fix) |
|---|---|---|---|---|
| Language | C++/Qt6 | C++/Qt6 | Rust/GPUI | Rust/GPUI |
| Tray | `QSystemTrayIcon` (SNI) | `QSystemTrayIcon` (SNI) | `tray-icon`/`muda` (SNI) | ksni (SNI, vendored+patched) |
| Process model | Single | Single | Split (tray + settings) | Single (tray + settings) |
| `ProvideXdgActivationToken` | yes (Qt) | yes (Qt) | **no** (root cause) | **yes** (ksni patch) |
| Window raise | `raise()` + `activateWindow()` | `raise()` + `activateWindow()` | IPC → `activate_window()` | `activate_with_token(token)` |
| GNOME tray raise | Works | Works | **Broken** (demand-attention popup) | **Works** |


## Why Netkeep's Case is Worse

1. **Cross-process IPC:** The tray process owns the user gesture but the settings process
   owns the window surface. The compositor sees two unrelated PIDs.

2. **No activation token path:** The Unix socket IPC (`activate:\n`) carries no token.
   Even if the tray process could obtain a token, it doesn't forward it.

3. **GPUI is not Qt:** Unlike `QWidget::activateWindow()` which at least tries
   `xdg_activation_v1` internally, GPUI's `activate_window()` is a platform-level call
   that has no Wayland token support out of the box.

## Fix Options

### Option 1: Merge tray into the GPUI process (recommended)

Move `run_tray_monitor` into the same process as `run_settings`. Tray menu click fires
`window.activate_window()` directly — no IPC needed.

- Matches what Throne and Telegram Desktop do
- Eliminates the IPC boundary that prevents token propagation
- Most architecturally robust
- Biggest refactor: requires unifying the tray event loop with GPUI's app loop
- `muda`/`tray-icon` already run in the GPUI process for the decision dialog — extend to settings

### Option 2: Pass xdg-activation token over IPC

Keep the process split, but have the tray process obtain and forward an activation token:

1. In the tray process (GTK context), when "Settings…" is clicked, request a startup
   notification ID from GTK's `AppLaunchContext`
2. Send the token over the Unix socket: `activate:<token>\n`
3. In the settings process, set `XDG_ACTIVATION_TOKEN=<token>` before calling
   `activate_window()`

This is what Telegram Desktop does for notification clicks — but with `XDG_ACTIVATION_TOKEN`
propagated via environment variable.

- Minimal refactor
- The token source is unclear: GTK's `AppLaunchContext` gives startup IDs for *new* launches,
  not for raising existing windows. You'd need to use the lower-level
  `xdg_activation_v1::get_activation_token` request.
- Fragile: depends on GTK/wayland-client bindings exposing the right API

### Option 3: Use `org.freedesktop.Application` D-Bus activation

Register the settings process as a `org.freedesktop.Application` on the session bus. The tray
process sends `Activate` via D-Bus instead of the Unix socket.

- GNOME grants activation for well-known D-Bus names it recognizes as user-initiated
- Requires the settings process to register as a Flatpak-style application or use
  `org.freedesktop.Application` interface directly
- More complex than Option 1 but avoids IPC token gymnastics

### Option 4: `gtk_window_present_with_time` workaround (X11 only)

Uses `GDK_CURRENT_TIME` timestamp. Works on X11 where there's no activation token mechanism.
**Does not work on Wayland.** Not recommended.

## Recommendation

**Option 1 (merge processes)** is the correct long-term fix. Every working Linux tray app
(Throne, Telegram Desktop, KDE apps, GNOME apps) is single-process. The process split was
designed to isolate settings lifetime from the tray, but the tray icon already lives in the
GPUI process for the decision dialog — unify it.

**Status:** Option 1 has been implemented. The tray and settings window now run in the same
GPUI process. Clicking "Settings…" in the tray menu opens/activates the settings window
directly using `activate_window()` on the same Wayland connection. **But focus still fails on
GNOME/Wayland** — see the definitive root-cause analysis below.

## Definitive root cause (from Mutter source)

Reading GNOME/Mutter `src/wayland/meta-wayland-activation.c` settles earlier speculation:

**Tokens ARE stored globally**, in a compositor-wide `GHashTable *tokens` keyed by token
string (`meta_wayland_activation_init`). Cross-process / cross-connection token handoff is
supported by design. (Earlier notes claiming "per-display" storage were wrong.)

**The actual gate** is in `maybe_activate()` → `token_can_activate()`:

```c
static gboolean token_can_activate(MetaXdgActivationToken *token) {
  if (!token->seat)    return FALSE;   // token must have set_serial + seat
  if (!token->surface) return FALSE;   // token must have set_surface
  return keyboard_can_grab_surface(seat->keyboard, token->surface, token->serial)
      || seat_get_grab_info(seat, token->surface, token->serial, ...);
}
```

If a token object exists in the table but `token_can_activate()` returns FALSE, Mutter calls
`meta_window_set_demands_attention(window)` instead of `meta_window_activate_full()`. **That
"demands attention" state is the clickable popup the user sees.** The activation *request
reaches* Mutter (GPUI's trace `H1 calling xdg_activation_v1.activate` fires) but is silently
downgraded to demands-attention.

Two token sources we tried, both fail this gate:

1. **GPUI's own `activate()`** (no-arg) mints a token with `set_surface` + `set_serial` +
   `set_seat`, but the serial is `get_serial(MousePress)` from an old press on the settings
   window — too stale for `keyboard_can_grab_surface`. → demands-attention.

2. **GTK3's `startup_notify_id()`** mints a token via
   `gdk_wayland_app_launch_context_get_startup_notify_id`
   (`gdk/wayland/gdkapplaunchcontext-wayland.c`). It sets `set_serial(last_implicit_grab_serial,
   seat)` but sets `set_surface` **only if `gdk_wayland_device_get_focus(keyboard)` is
   non-NULL**. The tray process (AppIndicator) holds no keyboard-focused GTK window when the
   menu item is clicked, so `focus_window` is NULL → **token has no surface** →
   `token_can_activate` returns FALSE at the `!token->surface` check → demands-attention.

This is a **known GNOME limitation** that no tray app (Telegram, Qt apps, etc.) fully solves
for the re-open case: the tray click's implicit-grab serial does not map to a client surface
Mutter can verify, so the activation is downgraded. KDE/KWin and wlroots honor these requests
more liberally; Mutter does not.

**Conclusion:** neither single-process `activate()` nor cross-connection token minting passes
Mutter's `token_can_activate` gate for an already-open window activated from a tray menu.

## Why Qt apps (Windscribe, Telegram, Throne) work — and the actual fix

Reading Qt's qtwayland (`src/plugins/shellintegration/xdg-shell/qwaylandxdgshell.cpp`,
`QWaylandXdgSurface::requestActivate`) reveals the mechanism these apps rely on. After an SNI
tray "Show app" click, GNOME gives the app keyboard focus, sending `wl_keyboard.enter` with a
**fresh focus serial**. Qt's `requestActivate` attaches `display()->lastInputDevice()->serial()`
(the most recent serial of any input event, **including** that keyboard.enter) plus the focus
window's surface to the activation token. Mutter's `keyboard_can_grab_surface` then sees
`focus_surface == surface && focus_serial == serial` → **TRUE** → real activation.

GPUI had the same idea (`WaylandWindow::activate()` sets surface + serial + seat) but used
`SerialKind::MousePress` — the last *mouse press* serial — which is stale after a tray click.
Worse, GPUI's `wl_keyboard::Event::Enter` handler (`{ surface, .. }`) **discarded** the
keyboard-enter serial, so the focus serial was never tracked. GPUI's own comment admitted
"the activation is probably going to be rejected anyway."

### Resolution (SHIPPED, verified working 2026-07-15): ksni `ProvideXdgActivationToken`

The real root cause (discovered by reading the installed GNOME AppIndicator shell
extension source): the **compositor itself** mints the activation token and delivers it to
the app via the SNI D-Bus method `ProvideXdgActivationToken(token)`, immediately before
`Activate`. The extension's `open()` in `appIndicator.js`:

```js
await this.provideActivationToken(timestamp);   // compositor mints token, calls app
await this._proxy.ActivateAsync(x, y, ...);     // then activates
```

`provideActivationToken` mints the token with `global.create_app_launch_context(...).get_startup_notify_id(...)` — **inside GNOME Shell**, so it is authoritative for any of the app's surfaces, focused or not. Qt apps work because Qt's SNI code implements `ProvideXdgActivationToken`, stashes the token, and feeds it to `requestActivate()` → `xdg_activation_v1.activate()`. The old `tray-icon`/libappindicator did **not** implement the method, so the extension got `UNKNOWN_METHOD`, gave up, and the token was never delivered — our self-activation had no authoritative token → Mutter's `token_can_activate` failed → `set_demands_attention` (the clickable popup).

The GTK `startup_notify_id` / `mint_activation_token` approach documented above was solving the wrong problem (an app-minted token is never authoritative for raising its own background window) and has been removed.

**What shipped:**

1. **Vendored ksni** (`crates/ksni/`, ksni 0.3.5) patched to add `ProvideXdgActivationToken`:
   - `src/dbus_interface.rs` — SNI interface method `provide_xdg_activation_token(token)`.
   - `src/lib.rs` — `Tray::on_activation_token(&mut self, token)` hook.
   - `src/service.rs` — `call_provide_xdg_activation_token`.
   (Upstream ksni 0.2.2/0.3.5 do not implement this method.)
2. **`apps/gpui/src/tray.rs`** — `LogiTray` SNI impl. `on_activation_token` stashes the
   token; the "Settings…" menu `activate` closure takes it and sends
   `TrayAction::Settings { token }` over std::mpsc to the GPUI main loop. ksni's service
   runs on a dedicated current-thread tokio runtime thread.
3. **`apps/gpui/src/main.rs`** `run_tray_monitor` — polls the action channel; on `Settings`
   calls `window.activate_window()` + `activate_with_token(token)`.
4. **GPUI fork** (`https://github.com/mohamadkhani/zed`, branch `netkeep/activate-with-token`,
   rev `c612da65`, rebased on zed HEAD `424a6824`) provides
   `Window::activate_with_token(&str)` → `xdg_activation_v1.activate(token, surface)`.
   Wired in via `[patch."https://github.com/zed-industries/zed"]` in the workspace root
   `Cargo.toml` (redirects `gpui`/`gpui_platform`/`gpui_macros`/`gpui_web`). Upstreaming
   proposal: zed discussion #61820.

Removed: `tray-icon`, `muda`, `gtk` deps (and the GTK C-FFI `mint_activation_token`).
Architecture: tray + settings in one GPUI process; the `--settings` subprocess is gone.

Why this works where GTK-minting didn't: the token is **compositor-minted**, so Mutter
honors it regardless of which Wayland connection owns the window. Single-connection is not
required.


## References

- [Throne — `ActivateWindow()` in `src/global/Utils.cpp`](https://github.com/throneproj/Throne/blob/main/src/global/Utils.cpp)
- [Throne — tray signal wiring in `src/ui/mainwindow.cpp`](https://github.com/throneproj/Throne/blob/main/src/ui/mainwindow.cpp)
- [Telegram Desktop — `MainWindow::activate()` in `window/main_window.cpp`](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/window/main_window.cpp)
- [Telegram Desktop — Linux notification token handling in `notifications_manager_linux.cpp`](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/platform/linux/notifications_manager_linux.cpp)
- [xdg-activation-v1 protocol spec](https://wayland.app/protocols/xdg-activation-v1)
- [Mutter — `meta-wayland-activation.c` (token_can_activate / maybe_activate)](https://github.com/GNOME/mutter/blob/master/src/wayland/meta-wayland-activation.c)
- [GTK3 — `gdkapplaunchcontext-wayland.c` (startup_notify_id token creation)](https://github.com/GNOME/gtk/blob/gtk-3-24/gdk/wayland/gdkapplaunchcontext-wayland.c)
- [Cross-process window activation on Wayland — GNOME Discourse](https://discourse.gnome.org/t/cross-process-window-activation-on-wayland/20306)
- [Supporting Wayland's XDG activation protocol with GTK/GLib — palant.info](https://palant.info/2026/02/03/supporting-waylands-xdg-activation-protocol-with-gtk/glib/)
