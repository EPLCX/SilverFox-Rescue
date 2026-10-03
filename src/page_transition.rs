//! Short page crossfades using the last displayed back-buffer frame.
use std::{cell::RefCell, time::{Duration, Instant}};
use windows_sys::Win32::{
    Foundation::{HWND, RECT},
    Graphics::Gdi::{
        AlphaBlend, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC,
        DeleteObject, InvalidateRect, SelectObject, AC_SRC_OVER, BLENDFUNCTION,
        HBITMAP, HDC, HGDIOBJ, SRCCOPY,
    },
    UI::WindowsAndMessaging::{
        GetClientRect, IsIconic, KillTimer, SetTimer, SystemParametersInfoW,
        SPI_GETCLIENTAREAANIMATION,
    },
};

pub const TIMER: usize = 0x5348;
const DURATION: Duration = Duration::from_millis(150);

struct Frame {
    dc: HDC,
    bitmap: HBITMAP,
    previous: HGDIOBJ,
}

impl Frame {
    unsafe fn capture(source: HDC, width: i32, height: i32) -> Option<Self> {
        let dc = CreateCompatibleDC(source);
        if dc.is_null() { return None; }
        let bitmap = CreateCompatibleBitmap(source, width, height);
        if bitmap.is_null() { DeleteDC(dc); return None; }
        let previous = SelectObject(dc, bitmap);
        let frame = Self { dc, bitmap, previous };
        if BitBlt(dc, 0, 0, width, height, source, 0, 0, SRCCOPY) == 0 {
            return None;
        }
        Some(frame)
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
    frame: Option<Frame>,
    started: Option<Instant>,
}

thread_local! {
    static TRANSITION: RefCell<Transition> = RefCell::new(Transition::default());
}

unsafe fn enabled() -> bool {
    let mut enabled = 1i32;
    SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&mut enabled as *mut i32).cast(), 0);
    enabled != 0
}

// Capture before the cached surface is repainted. A second navigation during a
// fade starts from the currently displayed blend, so rapid clicks stay smooth.
pub unsafe fn begin_frame(hwnd: HWND, source: HDC, client: &RECT, top: i32, page: (usize, usize)) -> bool {
    TRANSITION.with(|slot| {
        let mut transition = slot.borrow_mut();
        let size = (client.right, client.bottom);
        if transition.page != Some(page) {
            let animate = transition.page.is_some() && transition.size == size
                && size.0 > 0 && size.1 > top && IsIconic(hwnd) == 0 && enabled();
            transition.frame = if animate { Frame::capture(source, size.0, size.1) } else { None };
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
        transition.frame.is_some()
    })
}

pub unsafe fn blend(hwnd: HWND, destination: HDC) {
    TRANSITION.with(|slot| {
        let mut transition = slot.borrow_mut();
        let Some(started) = transition.started else { return; };
        let t = (started.elapsed().as_secs_f32() / DURATION.as_secs_f32()).clamp(0.0, 1.0);
        if t >= 1.0 {
            transition.frame = None;
            transition.started = None;
            KillTimer(hwnd, TIMER);
            return;
        }
        let Some(frame) = transition.frame.as_ref() else { return; };
        let eased = t * t * (3.0 - 2.0 * t);
        let alpha = ((1.0 - eased) * 255.0).round() as u8;
        let (width, bottom) = transition.size;
        let top = transition.top;
        if AlphaBlend(destination, 0, top, width, bottom - top, frame.dc, 0, top, width, bottom - top,
            BLENDFUNCTION { BlendOp: AC_SRC_OVER as u8, BlendFlags: 0, SourceConstantAlpha: alpha, AlphaFormat: 0 }) == 0 {
            transition.frame = None;
            transition.started = None;
            KillTimer(hwnd, TIMER);
        }
    });
}

pub unsafe fn tick(hwnd: HWND) {
    if IsIconic(hwnd) != 0 { clear(hwnd); return; }
    let top = TRANSITION.with(|slot| {
        let transition = slot.borrow();
        if transition.frame.is_none() { return None; }
        Some(transition.top)
    });
    if let Some(top) = top {
        let mut content: RECT = std::mem::zeroed();
        GetClientRect(hwnd, &mut content);
        content.top = top;
        InvalidateRect(hwnd, &content, 0);
    } else {
        KillTimer(hwnd, TIMER);
    }
}

pub unsafe fn clear(hwnd: HWND) {
    KillTimer(hwnd, TIMER);
    TRANSITION.with(|slot| *slot.borrow_mut() = Transition::default());
}
