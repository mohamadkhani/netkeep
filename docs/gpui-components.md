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

### Example: Decision Dialog

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

## Theme Customization (Advanced)

Custom themes are possible but require deeper configuration. For most cases, use built-in `ThemeMode::Dark` / `ThemeMode::Light` and override colors manually with GPUI's `.bg(color)` and `.text_color(color)` methods.

## Component Library Limitations

- No built-in `Input` or `Select` in 0.5.1 — use custom GPUI elements
- No built-in `Modal` or `Dialog` — build with `v_flex()` and positioning
- No built-in `Sidebar` or `Tabs` — implement with flexbox
- Theme customization is limited to two modes (Dark/Light)

For a robust, feature-rich UI, gpui-component provides the essentials; custom GPUI elements handle specialized needs.
