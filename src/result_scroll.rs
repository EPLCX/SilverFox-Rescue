//! Pixel scrolling shared by wheel animation and Windows pan gestures.
#[derive(Default)]
pub struct ResultScroll { pub position:f64, pub target:f64, pub pan:Option<i32>, pub dragged:bool }
impl ResultScroll {
    pub fn move_by(&mut self,delta:f64,max:f64,animate:bool){
        self.target=(self.target+delta).clamp(0.0,max);
        if !animate{self.position=self.target;}
    }
    pub fn tick(&mut self,max:f64)->bool{
        self.target=self.target.clamp(0.0,max);self.position=self.position.clamp(0.0,max);
        let remaining=self.target-self.position;
        if remaining.abs()<0.5{self.position=self.target;false}else{self.position+=remaining*0.25;true}
    }
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn wheel_interpolates_and_stops_at_viewport_boundary(){
        let mut scroll=ResultScroll::default();scroll.move_by(112.0,200.0,true);
        assert_eq!(scroll.position,0.0);assert!(scroll.tick(200.0));assert_eq!(scroll.position,28.0);
        for _ in 0..40{scroll.tick(200.0);}assert_eq!(scroll.position,112.0);
        scroll.move_by(1000.0,200.0,false);assert_eq!(scroll.position,200.0);
        scroll.move_by(-1000.0,200.0,false);assert_eq!(scroll.position,0.0);
    }
    #[test]fn resize_clamps_position_and_target(){let mut scroll=ResultScroll{position:400.0,target:500.0,pan:None,dragged:false};assert!(!scroll.tick(100.0));assert_eq!(scroll.position,100.0);assert_eq!(scroll.target,100.0);}
}
