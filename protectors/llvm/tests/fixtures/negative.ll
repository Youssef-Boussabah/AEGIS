; Explicit opt-in does not imply every function or instruction is supported.
define i32 @plain(i32 %a, i32 %b) {
  %v = add i32 %a, %b
  ret i32 %v
}
define i32 @flagged(i32 %a, i32 %b) #0 {
  %x = add nsw i32 %a, %b
  %y = add nuw i32 %x, %b
  %z = add nuw nsw i32 %y, %b
  ret i32 %z
}
define i1 @bit(i1 %a, i1 %b) #0 {
  %v = add i1 %a, %b
  ret i1 %v
}
define i129 @too_wide(i129 %a, i129 %b) #0 {
  %v = add i129 %a, %b
  ret i129 %v
}
define i32 @vectors(<2 x i32> %a, <2 x i32> %b) #0 {
  %v = add <2 x i32> %a, %b
  %r = extractelement <2 x i32> %v, i32 0
  ret i32 %r
}
define i32 @vector_inside(i32 %a, i32 %b) #0 {
  %v = add <2 x i32> <i32 1, i32 2>, <i32 3, i32 4>
  %r = extractelement <2 x i32> %v, i32 0
  ret i32 %r
}
define i32 @pointer(ptr %p, i32 %a) #0 {
  %v = add i32 %a, 1
  ret i32 %v
}
define i32 @varargs(i32 %a, ...) #0 {
  %v = add i32 %a, 1
  ret i32 %v
}
define void @void_return(i32 %a) #0 {
  %v = add i32 %a, 1
  ret void
}
define i32 @off(i32 %a, i32 %b) #1 {
  %v = add i32 %a, %b
  ret i32 %v
}
define i32 @indeterminate(i32 %a) #0 {
  %x = add i32 %a, undef
  %y = add i32 %x, poison
  ret i32 %y
}
define i32 @no_add(i32 %a, i32 %b) #0 {
  %v = xor i32 %a, %b
  ret i32 %v
}
declare i32 @external(i32, i32) #0
attributes #0 = { "aegis.protect" }
attributes #1 = { noinline optnone "aegis.protect" }
