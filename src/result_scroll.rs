//! Wheel animation uses elapsed time; touch and precision wheel input stay direct.
use std::time::{Duration,Instant};
const DURATION:Duration=Duration::from_millis(140);
#[derive(Default)]
pub struct ResultScroll {
    pub position:f64, pub target:f64, pub pan:Option<i32>, pub dragged:bool,
    animation:Option<(Instant,f64)>,
}
impl ResultScroll {
    pub fn animating(&self)->bool{self.animation.is_some()}
    pub fn stop(&mut self){self.animation=None;self.target=self.position;}
    pub fn move_by(&mut self,delta:f64,max:f64,animate:bool,now:Instant){
        self.tick(max,now);
        // Reversing direction starts from the displayed position, not the queued endpoint.
        let base=if !animate||delta*(self.target-self.position)<0.0{self.position}else{self.target};
        self.target=(base+delta).clamp(0.0,max);
        if animate&&(self.target-self.position).abs()>=0.5{self.animation=Some((now,self.position));}
        else{self.position=self.target;self.animation=None;}
    }
    pub fn tick(&mut self,max:f64,now:Instant)->bool{
        self.target=self.target.clamp(0.0,max);self.position=self.position.clamp(0.0,max);
        let Some((started,from))=self.animation else{return false;};
        let t=(now.saturating_duration_since(started).as_secs_f64()/DURATION.as_secs_f64()).min(1.0);
        self.position=(from+(self.target-from)*(1.0-(1.0-t).powi(3))).clamp(0.0,max);
        if t>=1.0||(self.target-self.position).abs()<0.5{self.position=self.target;self.animation=None;}
        self.animating()
    }
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn frame_delays_do_not_change_the_curve_or_extend_its_duration(){
        let now=Instant::now();let mut regular=ResultScroll::default();let mut delayed=ResultScroll::default();
        regular.move_by(112.0,200.0,true,now);delayed.move_by(112.0,200.0,true,now);
        for ms in [16,32,48,64,80]{regular.tick(200.0,now+Duration::from_millis(ms));}
        delayed.tick(200.0,now+Duration::from_millis(80));assert_eq!(regular.position,delayed.position);
        assert!(!delayed.tick(200.0,now+Duration::from_millis(300)));assert_eq!(delayed.position,112.0);
    }
    #[test]fn reversal_and_precision_input_respond_immediately(){
        let now=Instant::now();let mut scroll=ResultScroll::default();scroll.move_by(112.0,500.0,true,now);
        scroll.tick(500.0,now+Duration::from_millis(32));let displayed=scroll.position;
        scroll.move_by(-40.0,500.0,true,now+Duration::from_millis(32));assert_eq!(scroll.target,displayed-40.0);
        scroll.move_by(3.0,500.0,false,now+Duration::from_millis(40));assert_eq!(scroll.position,scroll.target);assert!(!scroll.animating());
        scroll.move_by(-1000.0,500.0,false,now);assert_eq!(scroll.position,0.0);
    }
    #[test]fn resize_and_boundary_stop_the_animation(){
        let now=Instant::now();let mut scroll=ResultScroll::default();scroll.move_by(400.0,500.0,false,now);scroll.move_by(100.0,500.0,true,now);
        assert!(!scroll.tick(100.0,now));assert_eq!(scroll.position,100.0);assert_eq!(scroll.target,100.0);
        scroll.move_by(100.0,100.0,true,now);assert!(!scroll.animating());
    }
}
