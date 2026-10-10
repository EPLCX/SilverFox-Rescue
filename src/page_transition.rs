//! Short entrances for changing content; shared controls and the footer stay still.
use std::{cell::RefCell, time::{Duration, Instant}};
use windows_sys::Win32::{
    Foundation::{HWND, RECT},
    Graphics::Gdi::{
        AlphaBlend, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC,
        DeleteObject, FillRect, GetStockObject, InvalidateRect, SelectObject,
        AC_SRC_OVER, BLENDFUNCTION, HBITMAP, HDC, HGDIOBJ, SRCCOPY, WHITE_BRUSH,
    },
    UI::WindowsAndMessaging::{
        IsIconic, KillTimer, SetTimer, SystemParametersInfoW,
        SPI_GETCLIENTAREAANIMATION,
    },
};

pub const TIMER: usize = 0x5348;
const DURATION: Duration = Duration::from_millis(240);

// Zero velocity and acceleration at both ends, without overshoot.
pub fn ease(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    t * t * t * (t * (t * 6.0 - 15.0) + 10.0)
}

pub struct Control {
    pub id: usize,
    pub rect: RECT,
    pub label: String,
}

impl Control {
    fn same_as(&self, other: &Self) -> bool {
        self.id == other.id && self.label == other.label
            && self.rect.left == other.rect.left && self.rect.top == other.rect.top
            && self.rect.right == other.rect.right && self.rect.bottom == other.rect.bottom
    }
}

struct Frame {
    dc: HDC,
    bitmap: HBITMAP,
    previous: HGDIOBJ,
}

impl Frame {
    unsafe fn create(source: HDC, width: i32, height: i32) -> Option<Self> {
        let dc = CreateCompatibleDC(source);
        if dc.is_null() { return None; }
        let bitmap = CreateCompatibleBitmap(source, width, height);
        if bitmap.is_null() { DeleteDC(dc); return None; }
        let previous = SelectObject(dc, bitmap);
        Some(Self { dc, bitmap, previous })
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        unsafe {
            SelectObject(self.dc, self.previous);
            DeleteObject(self.bitmap);
            DeleteDC(self.dc);
        }
    }
}

#[derive(Default)]
struct Transition {
    page: Option<(usize, usize)>,
    size: (i32, i32),
    top: i32,
    bottom: i32,
    distance: i32,
    offset: i32,
    progress: f32,
    controls: Vec<Control>,
    fixed: Vec<usize>,
    frame: Option<Frame>,
    started: Option<Instant>,
}

thread_local! {
    static TRANSITION: RefCell<Transition> = RefCell::new(Transition::default());
}

pub unsafe fn enabled() -> bool {
    let mut enabled = 1i32;
    SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&mut enabled as *mut i32).cast(), 0);
    enabled != 0
}

pub unsafe fn begin_frame(hwnd: HWND, source: HDC, client: &RECT, top: i32, dpi: i32,
    page: (usize, usize), controls: Vec<Control>) -> bool {
    TRANSITION.with(|slot| {
        let mut transition = slot.borrow_mut();
        let size = (client.right, client.bottom);
        let bottom = client.bottom - 48 * dpi / 96;
        if transition.page != Some(page) {
            let animate = transition.page.is_some() && transition.size == size
                && size.0 > 0 && bottom > top && IsIconic(hwnd) == 0 && enabled();
            transition.fixed = controls.iter().filter(|control|
                transition.controls.iter().any(|previous|control.same_as(previous)))
                .map(|control|control.id).collect();
            transition.frame = if animate { Frame::create(source, size.0, size.1) } else { None };
            transition.started = transition.frame.as_ref().map(|_| Instant::now());
            transition.page = Some(page);
            if transition.frame.is_some() && SetTimer(hwnd, TIMER, 16, None) == 0 {
                transition.frame = None;
                transition.started = None;
            }
            if transition.frame.is_none() { KillTimer(hwnd, TIMER); }
        } else if transition.size != size {
            transition.frame = None;
            transition.started = None;
            KillTimer(hwnd, TIMER);
        }
        transition.size = size;
        transition.top = top;
        transition.bottom = bottom;
        transition.distance = 16 * dpi / 96;
        transition.controls = controls;
        transition.progress = transition.started.map_or(1.0, |started|
            ease(started.elapsed().as_secs_f32() / DURATION.as_secs_f32()));
        if transition.progress >= 1.0 {
            transition.frame = None;
            transition.started = None;
            KillTimer(hwnd, TIMER);
        }
        transition.offset = if transition.frame.is_some() {
            ((1.0 - transition.progress) * transition.distance as f32).round() as i32
        } else { 0 };
        transition.frame.is_some()
    })
}

pub unsafe fn blend(hwnd: HWND, destination: HDC) {
    TRANSITION.with(|slot| {
        let mut transition = slot.borrow_mut();
        let Some(frame) = transition.frame.as_ref() else { return; };
        let width = transition.size.0;
        let bottom = transition.bottom;
        let top = transition.top;
        let offset = transition.offset.min(width);
        let content = RECT { left: 0, top, right: width, bottom };
        let white = GetStockObject(WHITE_BRUSH);
        FillRect(frame.dc, &content, white);
        // Remove shared buttons from the moving source, then restore them in
        // place. This also prevents a shifted duplicate of the same button.
        let fixed: Vec<RECT> = transition.controls.iter()
            .filter(|control|transition.fixed.contains(&control.id))
            .map(|control|control.rect)
            .filter(|rect|rect.top >= top && rect.bottom <= bottom).collect();
        for rect in &fixed {
            if BitBlt(frame.dc, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
                destination, rect.left, rect.top, SRCCOPY) == 0 { return; }
        }
        for rect in &fixed { FillRect(destination, rect, white); }
        let moved = offset == 0 || BitBlt(destination, offset, top, width - offset, bottom - top,
            destination, 0, top, SRCCOPY) != 0;
        let exposed = RECT { right: offset, ..content };
        FillRect(destination, &exposed, white);
        let blended = AlphaBlend(destination, 0, top, width, bottom - top,
            frame.dc, 0, top, width, bottom - top, BLENDFUNCTION {
                BlendOp: AC_SRC_OVER as u8, BlendFlags: 0,
                SourceConstantAlpha: ((1.0 - transition.progress) * 255.0).round() as u8,
                AlphaFormat: 0,
            }) != 0;
        for rect in &fixed {
            BitBlt(destination, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
                frame.dc, rect.left, rect.top, SRCCOPY);
        }
        if !moved || !blended {
            transition.frame = None;
            transition.started = None;
            transition.offset = 0;
            KillTimer(hwnd, TIMER);
            InvalidateRect(hwnd, &content, 0);
        }
    });
}

pub unsafe fn tick(hwnd: HWND) {
    if IsIconic(hwnd) != 0 { clear(hwnd); return; }
    let content = TRANSITION.with(|slot| {
        let transition = slot.borrow();
        if transition.frame.is_none() { return None; }
        Some(RECT { left: 0, top: transition.top, right: transition.size.0, bottom: transition.bottom })
    });
    if let Some(content) = content {
        InvalidateRect(hwnd, &content, 0);
    } else {
        KillTimer(hwnd, TIMER);
    }
}

// Use the last painted offset for input and accessibility, not a newer timestamp.
pub fn display_rect(id: usize, mut rect: RECT) -> RECT {
    TRANSITION.with(|slot| {
        let transition = slot.borrow();
        if rect.top >= transition.top && rect.bottom <= transition.bottom
            && !transition.fixed.contains(&id) {
            rect.left += transition.offset;
            rect.right += transition.offset;
        }
    });
    rect
}

pub fn content_offset() -> i32 {
    TRANSITION.with(|slot|slot.borrow().offset)
}

pub unsafe fn finish(hwnd: HWND) {
    TRANSITION.with(|slot| {
        let mut transition = slot.borrow_mut();
        if transition.frame.take().is_some() { InvalidateRect(hwnd, std::ptr::null(), 0); }
        transition.started = None;
        transition.offset = 0;
    });
    KillTimer(hwnd, TIMER);
}

pub unsafe fn clear(hwnd: HWND) {
    KillTimer(hwnd, TIMER);
    TRANSITION.with(|slot| *slot.borrow_mut() = Transition::default());
}
