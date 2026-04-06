// Named ANSI escape sequences used throughout the TUI.

// Screen
pub const alt_screen_enable = "\x1b[?1049h";
pub const alt_screen_disable = "\x1b[?1049l";

// Cursor visibility
pub const cursor_hide = "\x1b[?25l";
pub const cursor_show = "\x1b[?25h";

// Cursor positioning
pub const cursor_home = "\x1b[H";

// Erase
pub const clear_to_eol = "\x1b[K";

// Attributes
pub const reset = "\x1b[0m";
pub const reverse_video = "\x1b[7m";
pub const reverse_video_off = "\x1b[27m";

// Foreground colors
pub const fg_default = "\x1b[39m";
pub const fg_dark_gray = "\x1b[90m";
pub const fg_black = "\x1b[30m";

// Background colors
pub const bg_cursor_line = "\x1b[48;5;236m";
pub const bg_highlight = "\x1b[43m";

// Combined styles
pub const style_highlight = "\x1b[43;30m"; // yellow bg, black fg
pub const style_status = reverse_video;

// Box-drawing (UTF-8, not ANSI, but used as a separator constant)
pub const vertical_bar = "\xe2\x94\x82";

// 256-color foreground format: \x1b[38;5;{n}m
pub const fg_keyword = "\x1b[38;5;168m";
pub const fg_string = "\x1b[38;5;107m";
pub const fg_number = "\x1b[38;5;173m";
pub const fg_comment = "\x1b[38;5;243m";
pub const fg_builtin = "\x1b[38;5;109m";
pub const fg_type = "\x1b[38;5;180m";
pub const fg_asm_address = "\x1b[38;5;243m";
pub const fg_asm_mnemonic = "\x1b[38;5;75m";
pub const fg_asm_register = "\x1b[38;5;114m";
pub const fg_asm_immediate = "\x1b[38;5;173m";
pub const fg_asm_label = "\x1b[38;5;223m";

// Control characters
pub const key_ctrl_c: u8 = 0x03;
pub const key_ctrl_d: u8 = 0x04;
pub const key_ctrl_u: u8 = 0x15;
pub const key_escape: u8 = 0x1b;
pub const key_backspace: u8 = 0x7f;
pub const key_backspace_alt: u8 = 0x08;
pub const key_tab: u8 = '\t';
pub const key_enter: u8 = '\r';
pub const key_newline: u8 = '\n';
