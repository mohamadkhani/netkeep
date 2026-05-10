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
└── helpers.rs       # fetch_and_apply(), parse_dns_csv(), route_summary()
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

**Columns:** Name (140px) | Type (80px) | Targets (200px) | DNS (140px) | Status (80px) | Controls (80px)

**Cell rendering:**
- Col 0: Egress name + ID
- Col 1: Type badge (SYSTEM/PROXY/VPN/DIRECT)
- Col 2: Comma-separated target list
- Col 3: DNS servers
- Col 4: Active/Inactive status badge
- Col 5: Delete button

### ProxiesDelegate

**Columns:** Name (140px) | Protocol (80px) | Address (160px) | Auth (120px) | Status (80px) | Controls (140px)

**Cell rendering:**
- Col 0: Proxy name
- Col 1: Protocol badge (SOCKS5=green, HTTP=primary, Shadowsocks=teal)
- Col 2: host:port
- Col 3: Auth summary (None / user:*** / method)
- Col 4: Active/Inactive status badge
- Col 5: Toggle button + Delete button

## Dialog Usage

### Opening a Dialog on Double-Click

```rust
// Subscribe to table events in SettingsApp::new()
let sub = cx.subscribe_in(
    &egress_table,
    window,
    Self::on_egress_table_event,
);
subscriptions.push(sub);  // IMPORTANT: subscribe_in returns Subscription

// Handler
fn on_egress_table_event(
    &mut self,
    _table: &Entity<TableState<EgressDelegate>>,
    event: &TableEvent,
    window: &mut Window,
    cx: &mut Context<Self>,
) {
    if let TableEvent::DoubleClickedRow(row_ix) = event {
        let egresses = &self.state.read(cx).egresses;
        if let Some(egress) = egresses.get(*row_ix) {
            let egress = egress.clone();
            self.open_egress_detail_dialog(egress, window, cx);
        }
    }
}
```

### Dialog Construction Pattern

```rust
fn open_egress_detail_dialog(
    &mut self,
    egress: Egress,
    window: &mut Window,
    cx: &mut Context<Self>,
) {
    let name = egress.name.clone();
    let dns = egress.dns_servers.join(", ");

    window.open_dialog(cx, move |dialog, _, _| {
        dialog
            .title(format!("Egress: {name}"))
            .w(px(500.))
            .close_button(true)
            .child(
                v_flex()
                    .gap(px(12.))
                    .child(
                        div()
                            .text_color(colors::text())
                            // Use dns.clone() in else branch (Fn closure, not FnOnce)
                            .child(if dns.is_empty() { "—".to_string() } else { dns.clone() })
                    )
            )
            .on_ok(|_, _, _| true)
    });
}
```

### Critical: Fn vs FnOnce Closures

The dialog closure is `Fn` (called multiple times by the framework). This means:

```rust
// ❌ BROKEN: moves dns_clone, can't be called again
.child(if dns.is_empty() { "—".to_string() } else { dns_clone })

// ✅ CORRECT: clones in else branch, original stays usable
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

### Badge Element Helper

```rust
fn badge_el(label: &str, color: gpui::Hsla) -> gpui::AnyElement {
    div()
        .text_size(px(10.))
        .text_color(color)
        .px(px(6.))
        .py(px(2.))
        .rounded(px(3.))
        .border_1()
        .border_color(color)
        .bg(colors::bg())
        .child(label.to_string())
        .into_any_element()
}
```

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

- [ ] Editable fields in dialogs (currently read-only detail view)
- [ ] Add egress form dialog (name, targets, DNS)
- [ ] Add proxy form dialog (name, protocol, host, port, auth)
- [ ] Implement EgressTarget with priority ordering in table
- [ ] Drag-and-drop row reordering for priority
- [ ] Search/filter for rules table
- [ ] Bulk actions (enable/disable multiple rules)
