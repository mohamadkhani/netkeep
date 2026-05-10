# gpui-component 0.5.1 API Guide (Crates.io)

Library: https://crates.io/crates/gpui-component

## Initialization

Must call before using components:

```rust
fn main() {
    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);  // Initialize theme and resources
        
        // Now safe to use components
    });
}
```

## Theme

### Switching Theme

```rust
use gpui_component::{Theme, ThemeMode};

Theme::change(ThemeMode::Dark, None, cx);  // Dark mode
Theme::change(ThemeMode::Light, None, cx); // Light mode
```

- `ThemeMode::Dark` — dark background, light text
- `ThemeMode::Light` — light background, dark text
- Second arg `None` uses default theme; can pass custom theme struct

### Colors in Dark Mode

Default dark theme colors (approximate):
- Background: dark slate/navy
- Text: light gray/white
- Borders: medium gray
- Accents: blue, green, red

Theme colors are accessible to components automatically.

## Button Component

### Basic Button

```rust
use gpui_component::button::{Button, ButtonVariants as _};

Button::new("unique-id")
    .label("Click me")
    .on_click(|_, _, cx| {
        // Handle click
    })
```

Must provide unique string ID (e.g., `"deny-btn"`, `"allow-btn"`).

### Button Variants (Methods)

```rust
.label("Text")            // Button text
.on_click(callback)       // Click handler signature: |_, _, cx| { }
.success()                // Green button (Allow-like)
.danger()                 // Red button (Deny-like)
.warning()                // Yellow button
.w_full()                 // Full width
```

The `ButtonVariants as _` trait import adds `.success()`, `.danger()`, `.warning()` methods.

### Button Layout

```rust
Button::new("id")
    .label("Click")
    .w_full()  // Full width within parent flex container
```

Buttons inherit flexbox properties from parent container.

## Checkbox Component

### Basic Checkbox

```rust
use gpui_component::checkbox::Checkbox;

Checkbox::new("unique-id")
    .label("Option label")
    .checked(is_checked)
    .on_click({
        move |checked, _, cx| {
            // checked: &bool
            // Handle state update
        }
    })
```

Checkbox ID must be unique. `.on_click` receives `&bool` as first arg.

## Layout Components

From `gpui_component`:

```rust
use gpui_component::{h_flex, v_flex};
```

### Horizontal Flex (`h_flex`)

```rust
h_flex()
    .gap_3()            // Space between children
    .items_center()     // Vertical alignment
    .justify_between()  // Horizontal space distribution
    .px_4()             // Horizontal padding
    .child(element1)
    .child(element2)
```

Wraps `flex-direction: row`.

### Vertical Flex (`v_flex`)

```rust
v_flex()
    .size_full()        // Fill parent
    .gap_4()            // Space between children
    .items_center()     // Horizontal alignment
    .justify_center()   // Vertical alignment
    .px_5()             // Horizontal padding
    .py_4()             // Vertical padding
    .child(element1)
    .child(element2)
```

Wraps `flex-direction: column`.

### Layout Methods

Both `h_flex` and `v_flex` support all GPUI styling methods:
- `.gap_N()` — space between children
- `.items_center()` — cross-axis alignment
- `.justify_center()` — main-axis alignment
- `.justify_between()` — spread children apart
- `.px_N()`, `.py_N()` — padding
- `.w_full()`, `.h_px()` — sizing
- `.bg(color)` — background color

## Root Component

Wraps the main application view:

```rust
use gpui_component::Root;

cx.open_window(
    WindowOptions { ... },
    |window, cx| {
        let view = cx.new(|cx| MyView::new(state, cx));
        cx.new(|cx| Root::new(view, window, cx))
    },
)
```

`Root::new(view, window, cx)` is typically the outermost wrapper. It handles theme application and default styling.

## Combining Layout and Components

### Example: Decision Dialog (Legacy — Pre-MD3 Redesign)

> **Note:** The actual LogiGuard GPUI app now uses custom GPUI elements instead of
> gpui-component `Button` and `Checkbox` to match the Material Design 3 design spec.
> The segmented pill toggle, outlined action buttons, and grid layout are all built
> with raw `div()` + `h_flex()`/`v_flex()`. This example shows the general pattern.

```rust
v_flex()
    .size_full()
    .bg(color_bg())
    // Header
    .child(
        h_flex()
            .w_full()
            .items_center()
            .justify_between()
            .px_4()
            .py_3()
            .bg(color_amber_dim())
            .border_b_1()
            .border_color(color_amber())
            .child(
                div().text_color(color_amber()).child("⚠  WARNING")
            )
            .child(
                div().text_color(color_amber()).child("10s")
            )
    )
    // Content
    .child(
        v_flex()
            .flex_1()
            .px_5()
            .py_4()
            .gap_4()
            .child(
                Checkbox::new("remember")
                    .label("Remember this decision")
                    .checked(false)
                    .on_click({
                        move |checked, _, cx| {
                            // Update state
                        }
                    })
            )
    )
    // Footer buttons
    .child(
        h_flex()
            .w_full()
            .gap_3()
            .px_5()
            .py_4()
            .child(
                Button::new("deny")
                    .label("Deny")
                    .danger()
                    .w_full()
                    .on_click(|_, _, cx| { /* handle */ })
            )
            .child(
                Button::new("allow")
                    .label("Allow")
                    .success()
                    .w_full()
                    .on_click(|_, _, cx| { /* handle */ })
            )
    )
```

## Key Imports

```rust
use gpui_component::{
    Root,
    Theme,
    ThemeMode,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
    h_flex, v_flex,
};
```

## Common Patterns

### Conditional Component Visibility

```rust
.when(is_visible, |el| {
    el.child(Checkbox::new("id").label("Text"))
})
```

Requires `gpui::prelude::FluentBuilder as _` import from gpui (not gpui-component).

### Callback Closures

```rust
Button::new("id")
    .label("Click")
    .on_click({
        let state_weak = self.state.downgrade();
        move |_, _, cx| {
            if let Some(state) = state_weak.upgrade() {
                cx.update_entity(&state, |s, cx| {
                    s.field = new_value;
                    cx.notify();
                }).ok();
            }
        }
    })
```

Use block `{ ... }` to move bindings into closure. Capture weak refs to entities.

### Multiple Buttons in Row

```rust
h_flex()
    .w_full()
    .gap_3()  // Space between buttons
    .child(Button::new("btn1").label("Left").w_full())
    .child(Button::new("btn2").label("Right").w_full())
```

`.w_full()` on buttons makes them equally sized in flex row.

## Table Component

The `Table` component displays tabular data using a delegate pattern. It supports striped rows, column resizing, sorting, and row selection.

### Key Types

```rust
use gpui_component::table::{Table, TableDelegate, TableState, TableEvent, Column};
```

### TableDelegate Trait

Implement `TableDelegate` to provide data and rendering for a table:

```rust
struct MyDelegate {
    columns: Vec<Column>,
    items: Vec<MyItem>,
}

impl TableDelegate for MyDelegate {
    fn columns_count(&self, _cx: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _cx: &App) -> usize {
        self.items.len()
    }

    fn column(&self, col_ix: usize, _cx: &App) -> &Column {
        &self.columns[col_ix]
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        window: &mut Window,
        cx: &mut App,
    ) -> impl IntoElement {
        let item = &self.items[row_ix];
        match col_ix {
            0 => div().child(item.name.clone()),
            1 => div().child(item.value.to_string()),
            _ => div().child("—"),
        }
    }
}
```

**Key trait methods (all have default implementations except `render_td`):**
- `fn columns_count(&self, cx: &App) -> usize` — number of columns
- `fn rows_count(&self, cx: &App) -> usize` — number of rows
- `fn column(&self, col_ix: usize, cx: &App) -> &Column` — column definition (returns `&Column`, not `Column`)
- `fn render_td(&mut self, row_ix, col_ix, window, cx) -> impl IntoElement` — render a cell
- `fn render_tr(&mut self, row_ix, window, cx) -> Option<Div>` — customize row wrapper
- `fn render_th(&mut self, col_ix, window, cx) -> Option<Div>` — customize header cell
- `fn render_empty(&self, window, cx) -> Option<impl IntoElement>` — empty state
- `fn perform_sort(&mut self, col_ix, sort, window, cx)` — handle column sort
- `fn has_more(&self, cx: &App) -> bool` — for infinite scroll
- `fn load_more(&mut self, window, cx)` — load more data

### Column Definition

```rust
Column::new("id", "ID")
    .width(px(140.))
    .resizable(true)
    .sortable()

Column::new("actions", "Actions")
    .width(px(150.))
    .resizable(false)
```

- First arg: unique key (used for sort identification)
- Second arg: display name shown in header
- `.width(px(N))` — fixed column width
- `.resizable(bool)` — allow user to resize
- `.sortable()` — enable sort indicator
- `.fixed_left()` / `.fixed_right()` — freeze column

### Creating and Rendering Table

```rust
// In your view's new():
let table_state = cx.new(|cx| {
    TableState::new(my_delegate, window, cx)
        .row_selectable(true)
});

// In render():
Table::new(&self.table_state)
    .stripe(true)
    .bordered(true)
```

### Table Events

Subscribe to table events for row interactions:

```rust
cx.subscribe_in(&table_state, window, |view, _table, event, window, cx| {
    match event {
        TableEvent::DoubleClickedRow(row_ix) => {
            // Open detail dialog
        }
        TableEvent::SelectRow(row_ix) => {
            // Handle row selection
        }
        _ => {}
    }
});
```

**Important:** `subscribe_in` returns `Subscription`, NOT `()`. Store subscriptions in a Vec field to keep them alive:

```rust
struct MyView {
    table: Entity<TableState<MyDelegate>>,
    _subscriptions: Vec<Subscription>,
}
```

### TableState Methods

```rust
// Access delegate
table.delegate()          // &D
table.delegate_mut()      // &mut D

// Selection
table.set_selected_row(row_ix, cx);
table.selected_row()      // Option<usize>

// Refresh after data change
table.refresh(cx);
```

### Updating Delegate Data

```rust
self.table.update(cx, |table, _| {
    table.delegate_mut().items = new_items;
});
```

## Dialog Component

Modal dialogs for user interaction. Requires `Root` wrapper and `WindowExt` trait.

### Key Types

```rust
use gpui_component::dialog::Dialog;
use gpui_component::{Root, WindowExt as _};
```

### Opening a Dialog

```rust
// In a method with &mut Window and &mut Context<Self>:
window.open_dialog(cx, move |dialog, _, _| {
    dialog
        .title("Item Details")
        .w(px(500.))
        .close_button(true)
        .child(
            v_flex()
                .gap(px(12.))
                .child(div().child("Content here"))
        )
        .on_ok(|_, _, _| true)      // Return true to close
        .on_cancel(|_, _, _| true)   // Return true to close
});
```

**Dialog closure is `Fn` (not `FnOnce`):** All captured values must be re-usable. For `String` values used in both `.is_empty()` check and else branch, use `.clone()` in the else:

```rust
let name = item.name.clone();
window.open_dialog(cx, move |dialog, _, _| {
    dialog.child(
        div().child(if name.is_empty() { "—".into() } else { name.clone() })
    )
});
```

### Dialog Builder Methods

```rust
Dialog::new(window, cx)
    .title(impl IntoElement)     // Dialog title (any element)
    .w(px(500.))                 // Fixed width
    .max_w(px(600.))             // Max width
    .close_button(bool)          // Show X button
    .overlay(bool)               // Show backdrop overlay
    .overlay_closable(bool)      // Click overlay to close
    .keyboard(bool)              // Enable keyboard shortcuts
    .confirm()                   // OK/Cancel only
    .alert()                     // OK only
    .child(impl IntoElement)     // Add content
    .on_ok(|dialog, window, cx| bool)   // OK button handler
    .on_cancel(|dialog, window, cx| bool) // Cancel handler
    .on_close(|dialog, window, cx|)      // Close handler
```

### Root Requirement

Dialog requires `Root` as the outermost view wrapper:

```rust
cx.open_window(WindowOptions { ... }, |window, cx| {
    let view = cx.new(|cx| MyView::new(state, window, cx));
    cx.new(|cx| Root::new(view, window, cx))
});
```

## TabBar Component

Tab navigation for switching between views:

```rust
use gpui_component::tab::{Tab, TabBar};

TabBar::new("my-tabs")
    .selected_index(0)
    .on_click(cx.listener(|this, index: &usize, _, cx| {
        // Handle tab change
    }))
    .child(Tab::new("tab-0").label("Rules"))
    .child(Tab::new("tab-1").label("Egress"))
    .child(Tab::new("tab-2").label("Proxies"))
```

## Theme Customization (Advanced)

Custom themes are possible but require deeper configuration. For most cases, use built-in `ThemeMode::Dark` / `ThemeMode::Light` and override colors manually with GPUI's `.bg(color)` and `.text_color(color)` methods.

## Component Library Limitations (0.5.1)

- No built-in `Input` or `Select` in 0.5.1 — use custom GPUI elements
- No `DataTable` (git-only) — use `Table` with `TableDelegate` instead
- No `DialogHeader` / `DialogTitle` / `DialogFooter` (git-only) — use `Dialog::title()` and `.child()` instead
- Theme customization is limited to two modes (Dark/Light)

## Crates.io vs Git Version

The crates.io version (0.5.1) differs from the git repo version:

| Feature | crates.io 0.5.1 | git repo |
|---------|-----------------|----------|
| Table | ✅ `Table<D>` | ✅ `DataTable<D>` |
| TableDelegate | ✅ | ✅ |
| Dialog | ✅ basic (`Dialog::new`) | ✅ rich (`DialogHeader`, `DialogTitle`, etc.) |
| TabBar | ✅ | ✅ |
| Input/Select | ❌ | ✅ |
| Sizable | ✅ | ✅ |

**Official installation uses git repos:**
```toml
gpui = { git = "https://github.com/zed-industries/zed" }
gpui-component = { git = "https://github.com/longbridge/gpui-component" }
```

**Current project uses crates.io:**
```toml
gpui = "0.2"
gpui-component = "0.5"
```
