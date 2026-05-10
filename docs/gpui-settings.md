# Settings Window Architecture Guide

Complete guide to the LogiGuard settings window implementation using gpui-component Table and Dialog.

## Overview

The settings window is a separate GPUI process (`--settings` flag) that manages firewall rules, egress routes, and proxy configurations. It uses gpui-component's `Table` component with custom `TableDelegate` implementations for each tab, and `Dialog` for detail/edit views.

**Window size:** 960×720 pixels  
**Entry point:** [`main.rs::run_settings()`](../apps/gpui/src/main.rs)  
**Module:** [`settings/`](../apps/gpui/src/settings/)

## Architecture

### Process Model

```
Tray icon (main logiguard-gpui process)
  │
  ├── Monitor mode (default): polls daemon, spawns dialog per pending
  │
  └── --settings flag → std::process::Command::spawn()
       │
       └── Settings process (independent lifecycle)
            │
            ├── gpui_component::init(cx)
            ├── Theme::change(ThemeMode::Dark, None, cx)
            ├── fonts::apply_design_fonts(cx)
            │
            └── cx.open_window(...)
                 │ WindowOptions { size: 960×720, titlebar }
                 │
                 └── Root::new(SettingsApp, window, cx)  // Required for Dialog
```

### Component Hierarchy

```
Root
└── SettingsApp (Render)
    ├── TitleBar (drag, close, settings icon)
    ├── TabBar (Rules / Egress / Proxies)
    └── Table content area
        ├── Table<RulesDelegate>     (when Rules tab active)
        ├── Table<EgressDelegate>    (when Egress tab active)
        └── Table<ProxiesDelegate>   (when Proxies tab active)
```

### Data Flow

```
Daemon (Unix socket)
  │ ControlRequest::ListRules / ListEgresses / ListProxies
  │
  └──→ fetch_and_apply() [async, helpers.rs]
       │
       └──→ SettingsState entity update
            │
            └──→ cx.observe() triggers sync_tables()
                 │
                 ├── rules_table.update() → RulesDelegate.rules = ...
                 ├── egress_table.update() → EgressDelegate.egresses = ...
                 └── proxy_table.update() → ProxiesDelegate.proxies = ...
```

## File Structure

```
apps/gpui/src/settings/
├── mod.rs           # SettingsApp, SettingsState, tab switching, dialog handlers, Render
├── rules_tab.rs     # RulesDelegate (TableDelegate for firewall rules)
├── egress_tab.rs    # EgressDelegate (TableDelegate for egress routes)
├── proxies_tab.rs   # ProxiesDelegate (TableDelegate for proxy configs)
└── helpers.rs       # fetch_and_apply(), parse_dns_csv(), parse_targets_csv(), route_summary()

apps/gpui/src/components/
├── mod.rs           # re-exports all design-system primitives
└── modal.rs         # modal_header, modal_footer, field_label, table_badge, action_btn, proto_btn
```

## Key Types

### SettingsState

Shared state entity holding all data:

```rust
pub struct SettingsState {
    pub rules: Vec<core_types::Rule>,
    pub egresses: Vec<Egress>,
    pub proxies: Vec<ProxyConfig>,
    pub status: Option<String>,
    pub load_generation: u64,
    pub socket_path: String,
    pub active_tab: SettingsTab,
    /// Set by Edit button in proxy table rows; drained by SettingsApp observer.
    pub proxy_edit_request: Option<ProxyConfig>,
    /// Set by Edit button in egress table rows; drained by SettingsApp observer.
    pub egress_edit_request: Option<Egress>,
}
```

### SettingsApp

Main view holding table entities:

```rust
pub struct SettingsApp {
    state: Entity<SettingsState>,
    rules_table: Entity<TableState<RulesDelegate>>,
    egress_table: Entity<TableState<EgressDelegate>>,
    proxy_table: Entity<TableState<ProxiesDelegate>>,
    _subscriptions: Vec<Subscription>,  // Must keep alive!
}
```

## TableDelegate Implementations

### RulesDelegate

**Columns:** ID (140px) | Action (80px) | Destination (160px) | Route (100px) | Controls (150px, not resizable)

**Cell rendering:**
- Col 0: Green/red dot (enabled/disabled) + rule ID
- Col 1: Color-coded action badge (Allow=green, Deny=red, Ask=amber, Route=teal)
- Col 2: Destination value (domain, IP, CIDR)
- Col 3: Route target summary
- Col 4: Toggle button + Delete button (with async daemon call)

### EgressDelegate

**Columns:** Name (140px) | Type (80px) | Targets (200px) | DNS (140px) | Status (80px) | Controls (160px, not resizable)

**Cell rendering:**
- Col 0: Egress name (bold) + ID in parentheses (muted, 10px)
- Col 1: `table_badge` — SYSTEM/PROXY/VPN/DIRECT
- Col 2: Comma-separated target list (via `route_summary`)
- Col 3: DNS servers (or `—`)
- Col 4: `table_badge` — ACTIVE/INACTIVE
- Col 5: Edit button + Delete button (`action_btn`); hidden for system-default egress

### ProxiesDelegate

**Columns:** Name (140px) | Protocol (80px) | Address (160px) | Auth (120px) | Status (80px) | Controls (180px, not resizable)

**Cell rendering:**
- Col 0: Proxy name
- Col 1: `table_badge` — SOCKS5=green, HTTP=primary, SS=teal
- Col 2: host:port
- Col 3: Auth summary (None / user:*** / cipher-method)
- Col 4: `table_badge` — ACTIVE/INACTIVE
- Col 5: Edit button + Toggle button (`.border_color` override for toggle state) + Delete button (`action_btn`)

## Dialog Usage

### ⚠ render_dialog_layer — Required in Your Render Impl

**This is the most common mistake.** `window.open_dialog(...)` registers a dialog in `Root::active_dialogs`, but `Root::render` does **not** display it. You must call `Root::render_dialog_layer` at the end of your own `render()`:

```rust
impl Render for SettingsApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .child(/* title bar, tabs, table ... */)
            .children(footer_el)
            // ← REQUIRED or all open_dialog() calls are silent no-ops
            .children(Root::render_dialog_layer(window, &mut **cx))
            .into_any_element()
    }
}
```

`&mut **cx` is needed because `render_dialog_layer` expects `&mut App` but `cx` is `&mut Context<Self>`. Rust's auto-coercion works for method calls but not free-function call position — explicit double-deref is required.

### ⚠ `.confirm()` Is Required for Buttons to Appear

`on_ok` sets a callback but renders **no buttons**. You must call `.confirm()` (OK + Cancel) or `.alert()` (OK only):

```rust
// ❌ Dialog opens but has no buttons — can never be confirmed
dialog.on_ok(|_, _, _| true)

// ✅ Correct — footer with OK + Cancel
dialog
    .button_props(DialogButtonProps::default().ok_text("Save").cancel_text("Cancel"))
    .confirm()
    .on_ok(|_, _, _| true)
```

### Opening a Dialog on Button Click

Use `cx.listener` in `render()` — the callback receives `&mut Window`:

```rust
div()
    .id("add-proxy-btn")
    .on_click(cx.listener(|this, _, window, cx| {
        this.open_proxy_form_dialog(None, window, cx);
    }))
    .child("+ ADD PROXY")
```

### Opening a Dialog from a Table Row (Edit Button)

`TableDelegate::render_td` has no `&mut Window`, so you cannot call `open_dialog` directly. Instead, write a request into `SettingsState` and drain it from `observe_in`:

```rust
// In proxies_tab.rs render_td (controls column):
.on_click(move |_, _, cx| {
    if let Some(st) = state_edit.upgrade() {
        let _ = cx.update_entity(&st, |s: &mut SettingsState, cx| {
            s.proxy_edit_request = Some(proxy_edit.clone());
            cx.notify();   // triggers the observe_in below
        });
    }
})

// In SettingsApp::new():
cx.observe_in(&state, window, |this, _, window, cx| {
    this.sync_tables(cx);

    let edit = this.state.read(cx).proxy_edit_request.clone();
    if let Some(proxy) = edit {
        let _ = cx.update_entity(&this.state, |s, _cx| {
            s.proxy_edit_request = None;
            // ⚠ Do NOT call cx.notify() here — would re-trigger this observer
        });
        this.open_proxy_form_dialog(Some(proxy), window, cx);
        return;
    }

    cx.notify();
})
.detach();
```

### Double-Click on Row Opens Dialog

```rust
fn on_proxy_table_event(
    &mut self,
    _table: &Entity<TableState<ProxiesDelegate>>,
    event: &TableEvent,
    window: &mut Window,
    cx: &mut Context<Self>,
) {
    if let TableEvent::DoubleClickedRow(row_ix) = event {
        if let Some(proxy) = self.state.read(cx).proxies.get(*row_ix) {
            let proxy = proxy.clone();
            self.open_proxy_form_dialog(Some(proxy), window, cx);
        }
    }
}
```

### Form Dialog with Custom Header/Footer and Input Fields

All form dialogs use the `modal_header` / `modal_footer` pattern for a full-bleed title bar matching the design system. Create `InputState` entities **before** the dialog closure (closure is `Fn`, entities must exist before capture):

```rust
use crate::components::{field_label, modal_footer, modal_header, proto_btn};

fn open_proxy_form_dialog(
    &mut self,
    existing: Option<ProxyConfig>,
    window: &mut Window,
    cx: &mut Context<Self>,
) {
    let is_edit = existing.is_some();
    let (hdr_icon, hdr_title) = if is_edit { ("✏", "EDIT PROXY") } else { ("⊕", "ADD PROXY") };
    let ok_label = if is_edit { "Update" } else { "Add" };

    let init_name = existing.as_ref().map(|p| p.name.as_str()).unwrap_or("New Proxy");
    let name_input = cx.new(|cx| {
        let mut s = InputState::new(window, cx);
        s.set_value(init_name, window, cx);
        s
    });
    let name_c = name_input.clone();

    // Arc<Mutex<T>> for shared mutable state across Fn closure
    let selected_proto = Arc::new(Mutex::new(
        existing.as_ref().map(|p| p.protocol.clone()).unwrap_or(ProxyProtocol::Socks5)
    ));
    let proto_c = selected_proto.clone();

    window.open_dialog(cx, move |dialog, _, _cx| {
        let proto_for_ok = proto_c.clone();
        let name_for_ok = name_c.clone();

        dialog
            .p(px(0.))                  // zero padding → full-bleed title bar
            .close_button(false)        // modal_header provides ✕ button
            .title(modal_header(hdr_icon, hdr_title))
            .w(px(480.))
            .button_props(DialogButtonProps::default().ok_text(ok_label).cancel_text("Cancel"))
            .footer(|ok, cancel, w, cx| vec![modal_footer(cancel(w, cx), ok(w, cx))])
            .child(
                v_flex().px(px(16.)).py(px(16.)).gap(px(16.))
                    .child(v_flex().gap(px(4.))
                        .child(field_label("NAME"))
                        .child(Input::new(&name_c))
                    )
            )
            .on_ok(move |_, _, cx| {
                let name = name_for_ok.read(cx).value().to_string();
                let proto = proto_for_ok.lock().unwrap().clone();
                // ... create/update proxy ...
                true
            })
    });
}
```

**Pattern for egress form** (`open_egress_form_dialog`) is identical — fields differ (Name, Color, Targets CSV, DNS CSV). The `parse_targets_csv` helper converts the targets text field into `Vec<RouteTarget>`.

### `parse_targets_csv` — Egress Targets Field

Parses a comma-separated string like `"dev:eth0, tun:wg0, proxy:my-id"` into `Vec<RouteTarget>`:

```
tun:<name>   → RouteTarget::Tun(name)
proxy:<id>   → RouteTarget::Proxy(id)
dev:<name>   → RouteTarget::Device(name)
<bare>       → RouteTarget::Device(bare)     // fallback
```

Located in `settings/helpers.rs`.

### Critical: Fn vs FnOnce Closures

The dialog closure is `Fn` (called on every render frame while open). All captured values must support repeated use:

```rust
// ❌ BROKEN: moves dns, can't render again
.child(if dns.is_empty() { "—".to_string() } else { dns })

// ✅ CORRECT: clone in the branch that would consume
.child(if dns.is_empty() { "—".to_string() } else { dns.clone() })
```

## Common Patterns

### Async Delete with Daemon Call

```rust
// In render_td (Controls column):
let socket_path = self.socket_path.clone();
let weak = self.state_weak.clone();
let id_to_delete = item.id.clone();
let id_for_closure = id_to_delete.clone();

div()
    .child(
        Button::new(format!("delete-{id_to_delete}"))
            .label("✕")
            .on_click(move |_, _, cx| {
                let socket = socket_path.clone();
                let weak = weak.clone();
                let pid = id_for_closure.clone();
                cx.spawn(async move |_this, cx| {
                    let res = cx.background_executor().spawn(async move {
                        daemon::send_request(&socket, &ControlRequest::DeleteEgress { id: pid })
                    }).await;
                    if let Ok(ControlResponse::Ok) = res {
                        fetch_and_apply(weak, &socket, cx).await;
                    }
                }).detach();
            })
    )
```

### Toggle Enabled State

```rust
let new_enabled = !item.enabled;
let socket = self.socket_path.clone();
let weak = self.state_weak.clone();
let id = item.id.clone();

div()
    .child(
        div()
            .cursor_pointer()
            .on_click(move |_, _, cx| {
                let socket = socket.clone();
                let weak = weak.clone();
                let id = id.clone();
                cx.spawn(async move |_this, cx| {
                    let mut updated = item.clone();
                    updated.enabled = new_enabled;
                    let res = cx.background_executor().spawn(async move {
                        daemon::send_request(&socket, &ControlRequest::UpsertProxy(updated))
                    }).await;
                    if let Ok(ControlResponse::Ok) = res {
                        fetch_and_apply(weak, &socket, cx).await;
                    }
                }).detach();
            })
    )
```

### Design System Helpers (`components/modal.rs`)

All table and dialog primitives live in `apps/gpui/src/components/modal.rs` and are re-exported from `crate::components`:

```rust
use crate::components::{action_btn, field_label, modal_footer, modal_header, proto_btn, table_badge};
```

- `table_badge(label, color)` — inline bordered badge for Status/Type/Protocol columns
- `action_btn(id, label, color) -> Stateful<Div>` — small outline button; chain `.on_click(...)` directly
- `field_label(text)` — 10px bold muted uppercase label for form fields
- `modal_header(icon, title)` — full-bleed dialog title bar with ✕ close button
- `modal_footer(cancel, ok)` — styled footer bar accepting rendered button elements
- `proto_btn(label, text_color, border_color, on_click)` — protocol selector button for proxy form

## Gotchas and Lessons Learned

### 1. `subscribe_in` Returns `Subscription`, Not `()`

```rust
// ❌ BROKEN: .detach() doesn't exist on Subscription
cx.subscribe_in(&table, window, handler).detach();

// ✅ CORRECT: Store Subscription in Vec
let sub = cx.subscribe_in(&table, window, handler);
subscriptions.push(sub);
```

### 2. `column()` Returns `&Column`, Not `Column`

Store columns as `Vec<Column>` and return a reference:

```rust
struct MyDelegate {
    columns: Vec<Column>,
}

impl TableDelegate for MyDelegate {
    fn column(&self, col_ix: usize, _cx: &App) -> &Column {
        &self.columns[col_ix]
    }
}
```

### 3. `SettingsApp::new()` Needs `window` Parameter

```rust
// In main.rs open_window callback:
|window, cx| {
    let view = cx.new(|cx| SettingsApp::new(state, window, cx));
    cx.new(|cx| Root::new(view, window, cx))
}
```

### 4. `Context<Self>` Deref-Coercion to `App`

Methods like `state.read(cx)` expect `&App`, but `cx` is `&mut Context<Self>`. This works because `Context` derefs to `App`. Rust-analyzer may show false-positive errors here.

### 5. `window.open_dialog(cx, ...)` Signature

```rust
// cx is &mut Context<Self>, but open_dialog expects &mut App
// This works via deref coercion
window.open_dialog(cx, |dialog, _, _| { ... });
```

### 6. Borrow-After-Move in Closures

When using a value both in a request and a comparison, clone it before the closure:

```rust
let pid_req = proxy.id.clone();  // For the request
let pid_cmp = proxy.id.clone();  // For the comparison in retain()
cx.spawn(async move |_this, cx| {
    // Use pid_req for request, pid_cmp for retain
});
```

## Dependencies

```toml
# apps/gpui/Cargo.toml
[dependencies]
gpui = "0.2"
gpui-component = "0.5"
core-types.path = "../crates/core-types"
control-api.path = "../crates/control-api"
```

## Reference Files

The key files to understand are:

| File | Purpose |
|------|---------|
| [`settings/mod.rs`](../apps/gpui/src/settings/mod.rs) | Main settings app, tab switching, dialog handlers, render |
| [`settings/rules_tab.rs`](../apps/gpui/src/settings/rules_tab.rs) | RulesDelegate — rule table with toggle/delete |
| [`settings/egress_tab.rs`](../apps/gpui/src/settings/egress_tab.rs) | EgressDelegate — egress table with type badges |
| [`settings/proxies_tab.rs`](../apps/gpui/src/settings/proxies_tab.rs) | ProxiesDelegate — proxy table with protocol badges |
| [`settings/helpers.rs`](../apps/gpui/src/settings/helpers.rs) | Async data fetch, DNS parsing, route summary |
| [`main.rs`](../apps/gpui/src/main.rs) | Entry point, `run_settings()` function |
| [`colors.rs`](../apps/gpui/src/colors.rs) | Material Design 3 dark theme colors |
| [`daemon.rs`](../apps/gpui/src/daemon.rs) | Unix socket IPC helpers |

## Next Steps

- [x] Add proxy form dialog (name, protocol, host, port) — Add + Edit
- [x] Add egress form dialog (name, color, targets CSV, DNS CSV) — Add + Edit
- [x] Custom design-system modal header/footer — full-bleed title bar with ✕ button
- [x] Reusable `table_badge`, `action_btn`, `field_label`, `proto_btn` components in `components/modal.rs`
- [ ] Implement EgressTarget with priority ordering in table
- [ ] Auth fields in proxy form dialog (Basic / Shadowsocks)
- [ ] Drag-and-drop row reordering for egress priority
- [ ] Search/filter for rules table
- [ ] Bulk actions (enable/disable multiple rules)
