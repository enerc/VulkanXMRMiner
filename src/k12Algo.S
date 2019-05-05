#ifdef __aarch64__
.global algo_k12
#define BC0		q0
#define BC1		q1
#define BC2		q2
#define TMP0	q3
#define TMP1	q4
#define TMP2	q5
#define TMP3	q6
#define TMP4	q7
#define TMP5	q8
#define BC0v	v0
#define BC1v	v1
#define BC2v	v2
#define TMP0v	v3
#define TMP1v	v4
#define TMP2v	v5
#define TMP3v	v6
#define TMP4v	v7
#define TMP5v	v8
#define STi0 	x0
#define STi1 	x1
#define STi2 	x2
#define STi3 	x3
#define STi4 	x4
#define STi5 	x5
#define STi6 	x6
#define STi7 	x7
#define STi8 	x8
#define STi9 	x9
#define STi10 	x10
#define STi11 	x11
#define STi12 	x12
#define STi13 	x13
#define STi14 	x14
#define STi15 	x15
#define STi16 	x16
#define STi17 	x17
#define STi18 	x18
#define STi19 	x19
#define STi20 	x20
#define STi21 	x21
#define BCi0	x22
#define BCi1	x23
#define BCi2	x24
#define BCi3	x25
#define BCi4	x26
#define TMPi0	x27
#define TMPi1	x28
#define TMPi2	x29
#define TMPi3	x30
algo_k12:
	mov		BC1v.d[0],x0
	stp		x8,x9,[x0,#3*16]
	stp		x16,x17,[x0,#7*16]
	stp		x18,x19,[x0,#8*16]
	stp		x20,x21,[x0,#9*16]
	stp		x22,x23,[x0,#10*16]
	stp		x24,x25,[x0,#11*16]
	stp		x26,x27,[x0,#12*16]
	stp		x28,x29,[x0,#13*16]
	mov 	TMPi0,0xfff
	mov		BC0v.d[0],TMPi0
	adrp	x0, :got:keccakf_rndc
	ldr		x0, [x0, #:got_lo12:keccakf_rndc]
	mov		BC0v.d[1],x0
	ldp		STi2,STi3,[x1,#1*16]
	ldp		STi4,STi5,[x1,#2*16]
	ldp		STi6,STi7,[x1,#3*16]
	ldp		STi8,STi9,[x1,#4*16]
	ldp		STi10,STi11,[x1,#5*16]
	ldp		STi12,STi13,[x1,#6*16]
	ldp		STi14,STi15,[x1,#7*16]
	ldp		STi16,STi17,[x1,#8*16]
	ldp		STi18,STi19,[x1,#9*16]
	ldp		STi20,STi21,[x1,#10*16]
	ldr		TMP4,[x1,#11*16]
	ldr		TMP5,[x1,#12*16]
	ldp		STi0,STi1,[x1,#0*16]
	mov		TMP5v.d[1],x30
algo_k12_loop:
	mov		TMPi0,TMP4v.d[0]
	mov		TMPi2,TMP4v.d[1]
	eor		TMPi0,TMPi0,STi17
	eor		TMPi2,TMPi2,STi18
	eor		TMPi0,TMPi0,STi12
	eor		TMPi2,TMPi2,STi13
	eor		TMPi0,TMPi0,STi7
	eor		TMPi2,TMPi2,STi8
	eor		TMPi0,TMPi0,STi2
	eor		TMPi2,TMPi2,STi3
	lsl		TMPi1,TMPi0,#1
	lsl		TMPi3,TMPi2,#1
	lsr		TMPi0,TMPi0,#63
	lsr		TMPi2,TMPi2,#63
	orr		TMPi0,TMPi0,TMPi1
	orr		TMPi2,TMPi2,TMPi3
	eor		TMPi0,TMPi0,STi20
	eor		TMPi2,TMPi2,STi21
	eor		TMPi0,TMPi0,STi15
	eor		TMPi2,TMPi2,STi16
	eor		TMPi0,TMPi0,STi10
	eor		TMPi2,TMPi2,STi11
	eor		TMPi0,TMPi0,STi5
	eor		TMPi2,TMPi2,STi6
	eor		BCi0,TMPi0,STi0
	eor		BCi1,TMPi2,STi1
	mov		TMPi0,TMP5v.d[0]
	eor		TMPi0,TMPi0,STi19
	eor		TMPi2,STi20,STi15
	eor		TMPi0,TMPi0,STi14
	eor		TMPi2,TMPi2,STi10
	eor		TMPi0,TMPi0,STi9
	eor		TMPi2,TMPi2,STi5
	eor		TMPi0,TMPi0,STi4
	eor		TMPi2,TMPi2,STi0
	lsl		TMPi1,TMPi0,#1
	lsl		TMPi3,TMPi2,#1
	lsr		TMPi0,TMPi0,#63
	lsr		TMPi2,TMPi2,#63
	orr		TMPi0,TMPi0,TMPi1
	orr		TMPi2,TMPi2,TMPi3
	mov		TMPi1,TMP4v.d[0]
	mov		TMPi3,TMP4v.d[1]
	eor		TMPi0,TMPi0,TMPi1
	eor		TMPi2,TMPi2,TMPi3
	eor		TMPi0,TMPi0,STi17
	eor		TMPi2,TMPi2,STi18
	eor		TMPi0,TMPi0,STi12
	eor		TMPi2,TMPi2,STi13
	eor		TMPi0,TMPi0,STi7
	eor		TMPi2,TMPi2,STi8
	eor		BCi2,TMPi0,STi2
	eor		BCi3,TMPi2,STi3
	eor		TMPi0,STi1,STi6
	eor		TMPi2,STi4,STi9
	eor		TMPi0,TMPi0,STi11
	eor		TMPi2,TMPi2,STi14
	eor		TMPi0,TMPi0,STi16
	mov		TMPi3,TMP5v.d[0]
	eor		TMPi0,TMPi0,STi21
	eor		TMPi2,TMPi2,STi19
	lsl		TMPi1,TMPi0,#1
	lsr		TMPi0,TMPi0,#63
	eor		TMPi2,TMPi2,TMPi3
	orr		TMPi0,TMPi0,TMPi1
	eor		BCi4,TMPi2,TMPi0
	eor		STi0,STi0,BCi4
	eor		STi1,STi1,BCi0
	eor		STi2,STi2,BCi1
	eor		STi3,STi3,BCi2
	eor		STi4,STi4,BCi3
	eor		STi5,STi5,BCi4
	eor		STi6,STi6,BCi0
	eor		STi7,STi7,BCi1
	eor		STi8,STi8,BCi2
	eor		STi9,STi9,BCi3
	eor		STi10,STi10,BCi4
	eor		STi11,STi11,BCi0
	eor		STi12,STi12,BCi1
	eor		STi13,STi13,BCi2
	eor		STi14,STi14,BCi3
	eor		STi15,STi15,BCi4
	eor		STi16,STi16,BCi0
	eor		STi17,STi17,BCi1
	eor		STi18,STi18,BCi2
	eor		STi19,STi19,BCi3
	eor		STi20,STi20,BCi4
	eor		STi21,STi21,BCi0
	mov		TMPi0,TMP4v.d[0]
	mov		TMPi1,TMP4v.d[1]
	mov		TMPi2,TMP5v.d[0]
	eor		TMPi0,TMPi0,BCi1
	eor		TMPi1,TMPi1,BCi2
	eor		TMPi2,TMPi2,BCi3
	mov		TMP4v.d[0],TMPi0
	mov		TMP4v.d[1],TMPi1
	mov		TMP5v.d[0],TMPi2
	mov		BCi1,TMP4v.d[0]
	mov		BCi2,TMP4v.d[1]
	mov		BCi3,TMP5v.d[0]
	mov		TMPi0,STi10
	lsl		TMPi1,STi1,#1
	lsr		TMPi2,STi1,#(64-1)
	lsl		TMPi3,TMPi0,#3
	lsr		BCi0,TMPi0,#(64-3)
	mov		TMPi0,STi7
	orr		STi10,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#6
	lsr		TMPi2,TMPi0,#(64-6)
	mov		TMPi0,STi11
	orr		STi7,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#10
	lsr		BCi0,TMPi0,#(64-10)
	mov		TMPi0,STi17
	orr		STi11,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#15
	lsr		TMPi2,TMPi0,#(64-15)
	mov		TMPi0,STi18
	orr		STi17,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#21
	lsr		BCi0,TMPi0,#(64-21)
	mov		TMPi0,STi3
	orr		STi18,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#28
	lsr		TMPi2,TMPi0,#(64-28)
	mov		TMPi0,STi5
	orr		STi3,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#36
	lsr		BCi0,TMPi0,#(64-36)
	mov		TMPi0,STi16
	orr		STi5,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#45
	lsr		TMPi2,TMPi0,#(64-45)
	mov		TMPi0,STi8
	orr		STi16,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#55
	lsr		BCi0,TMPi0,#(64-55)
	mov		TMPi0,STi21
	orr		STi8,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#2
	lsr		TMPi2,TMPi0,#(64-2)
	mov		TMPi0,BCi3
	orr		STi21,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#14
	lsr		BCi0,TMPi0,#(64-14)
	mov		TMPi0,STi4
	orr		BCi3,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#27
	lsr		TMPi2,TMPi0,#(64-27)
	mov		TMPi0,STi15
	orr		STi4,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#41
	lsr		BCi0,TMPi0,#(64-41)
	mov		TMPi0,BCi2
	orr		STi15,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#56
	lsr		TMPi2,TMPi0,#(64-56)
	mov		TMPi0,STi19
	orr		BCi2,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#8
	lsr		BCi0,TMPi0,#(64-8)
	mov		TMPi0,STi13
	orr		STi19,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#25
	lsr		TMPi2,TMPi0,#(64-25)
	mov		TMPi0,STi12
	orr		STi13,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#43
	lsr		BCi0,TMPi0,#(64-43)
	mov		TMPi0,STi2
	orr		STi12,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#62
	lsr		TMPi2,TMPi0,#(64-62)
	mov		TMPi0,STi20
	orr		STi2,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#18
	lsr		BCi0,TMPi0,#(64-18)
	mov		TMPi0,STi14
	orr		STi20,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#39
	lsr		TMPi2,TMPi0,#(64-39)
	mov		TMPi0,BCi1
	orr		STi14,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#61
	lsr		BCi0,TMPi0,#(64-61)
	mov		TMPi0,STi9
	orr		BCi1,TMPi1,TMPi2
	lsl		TMPi1,TMPi0,#20
	lsr		TMPi2,TMPi0,#(64-20)
	mov		TMPi0,STi6
	orr		STi9,TMPi3,BCi0
	lsl		TMPi3,TMPi0,#44
	lsr		BCi0,TMPi0,#(64-44)
	orr		STi6,TMPi1,TMPi2
	orr		STi1,TMPi3,BCi0
	mov		TMP4v.d[0],BCi1
	mov		TMP4v.d[1],BCi2
	mov		TMP5v.d[0],BCi3
	mov		BCi0,STi0
	mov		BCi1,STi1
	eor		TMPi0,STi0,STi2
	mvn		TMPi1,STi1
	and		TMPi2,STi0,STi1
	and		TMPi3,TMPi0,TMPi1
	eor		TMPi0,STi1,STi3
	mvn		TMPi1,STi2
	orr		STi0,TMPi2,TMPi3
	and		TMPi2,STi1,STi2
	and		TMPi3,TMPi0,TMPi1
	eor		TMPi0,STi2,STi4
	orr		STi1,TMPi2,TMPi3
	mvn		TMPi1,STi3
	and		TMPi2,STi2,STi3
	and		TMPi3,TMPi0,TMPi1
	eor		TMPi0,STi3,BCi0
	orr		STi2,TMPi2,TMPi3
	mvn		TMPi1,STi4
	and		TMPi2,STi3,STi4
	and		TMPi3,TMPi0,TMPi1
	orr		STi3,TMPi2,TMPi3
	eor		TMPi0,STi4,BCi1
	mvn		TMPi1,BCi0
	and		TMPi2,STi4,BCi0
	and		TMPi3,TMPi0,TMPi1
	orr		STi4,TMPi2,TMPi3
	mov		BCi0,STi5
	mov		BCi1,STi6
	eor		TMPi0,STi5,STi7
	mvn		TMPi1,STi6
	and		TMPi2,STi5,STi6
	and		TMPi3,TMPi0,TMPi1
	orr		STi5,TMPi2,TMPi3
	eor		TMPi0,STi6,STi8
	mvn		TMPi1,STi7
	and		TMPi2,STi6,STi7
	and		TMPi3,TMPi0,TMPi1
	orr		STi6,TMPi2,TMPi3
	eor		TMPi0,STi7,STi9
	mvn		TMPi1,STi8
	and		TMPi2,STi7,STi8
	and		TMPi3,TMPi0,TMPi1
	orr		STi7,TMPi2,TMPi3
	eor		TMPi0,STi8,BCi0
	mvn		TMPi1,STi9
	and		TMPi2,STi8,STi9
	and		TMPi3,TMPi0,TMPi1
	orr		STi8,TMPi2,TMPi3
	eor		TMPi0,STi9,BCi1
	mvn		TMPi1,BCi0
	and		TMPi2,STi9,BCi0
	and		TMPi3,TMPi0,TMPi1
	orr		STi9,TMPi2,TMPi3
	mov		BCi0,STi10
	mov		BCi1,STi11
	eor		TMPi0,STi10,STi12
	mvn		TMPi1,STi11
	and		TMPi2,STi10,STi11
	and		TMPi3,TMPi0,TMPi1
	orr		STi10,TMPi2,TMPi3
	eor		TMPi0,STi11,STi13
	mvn		TMPi1,STi12
	and		TMPi2,STi11,STi12
	and		TMPi3,TMPi0,TMPi1
	orr		STi11,TMPi2,TMPi3
	eor		TMPi0,STi12,STi14
	mvn		TMPi1,STi13
	and		TMPi2,STi12,STi13
	and		TMPi3,TMPi0,TMPi1
	orr		STi12,TMPi2,TMPi3
	eor		TMPi0,STi13,BCi0
	mvn		TMPi1,STi14
	and		TMPi2,STi13,STi14
	and		TMPi3,TMPi0,TMPi1
	orr		STi13,TMPi2,TMPi3
	eor		TMPi0,STi14,BCi1
	mvn		TMPi1,BCi0
	and		TMPi2,STi14,BCi0
	and		TMPi3,TMPi0,TMPi1
	orr		STi14,TMPi2,TMPi3
	mov		BCi0,STi15
	mov		BCi1,STi16
	eor		TMPi0,STi15,STi17
	mvn		TMPi1,STi16
	and		TMPi2,STi15,STi16
	and		TMPi3,TMPi0,TMPi1
	orr		STi15,TMPi2,TMPi3
	eor		TMPi0,STi16,STi18
	mvn		TMPi1,STi17
	and		TMPi2,STi16,STi17
	and		TMPi3,TMPi0,TMPi1
	orr		STi16,TMPi2,TMPi3
	eor		TMPi0,STi17,STi19
	mvn		TMPi1,STi18
	and		TMPi2,STi17,STi18
	and		TMPi3,TMPi0,TMPi1
	orr		STi17,TMPi2,TMPi3
	eor		TMPi0,STi18,BCi0
	mvn		TMPi1,STi19
	and		TMPi2,STi18,STi19
	and		TMPi3,TMPi0,TMPi1
	orr		STi18,TMPi2,TMPi3
	eor		TMPi0,STi19,BCi1
	mvn		TMPi1,BCi0
	and		TMPi2,STi19,BCi0
	and		TMPi3,TMPi0,TMPi1
	orr		STi19,TMPi2,TMPi3
	mov		BCi0,STi20
	mov		BCi1,STi21
	mov		BCi3,TMP4v.d[0]
	mov		BCi4,TMP4v.d[1]
	mov		BCi2,TMP5v.d[0]
	eor		TMPi0,STi20,BCi3
	mvn		TMPi1,STi21
	and		TMPi2,STi20,STi21
	and		TMPi3,TMPi0,TMPi1
	orr		STi20,TMPi2,TMPi3
	eor		TMPi0,STi21,BCi4
	mvn		TMPi1,BCi3
	and		TMPi2,STi21,BCi3
	and		TMPi3,TMPi0,TMPi1
	orr		STi21,TMPi2,TMPi3
	eor		TMPi0,BCi3,BCi2
	mvn		TMPi1,BCi4
	and		TMPi2,BCi3,BCi4
	and		TMPi3,TMPi0,TMPi1
	orr		TMPi0,TMPi2,TMPi3
	mov		TMP4v.d[0],TMPi0
	eor		TMPi0,BCi4,BCi0
	mvn		TMPi1,BCi2
	and		TMPi2,BCi4,BCi2
	and		TMPi3,TMPi0,TMPi1
	orr		TMPi0,TMPi2,TMPi3
	mov		TMP4v.d[1],TMPi0
	eor		TMPi0,BCi2,BCi1
	mvn		TMPi1,BCi0
	and		TMPi2,BCi2,BCi0
	and		TMPi3,TMPi0,TMPi1
	mov		TMPi1,BC0v.d[1]
	orr		TMPi0,TMPi2,TMPi3
	ldr		TMPi2,[TMPi1],#8
	mov		TMP5v.d[0],TMPi0
	mov		TMPi0,BC0v.d[0]
	lsr		TMPi0,TMPi0,#1
	mov		BC0v.d[1],TMPi1
	mov		BC0v.d[0],TMPi0
	eor		STi0,STi0,TMPi2
	cbnz 	TMPi0,algo_k12_loop
	mov		x30,TMP5v.d[1]
	mov		x4,BC1v.d[0]
	ldp		x8,x9,[x4,#3*16]
	ldp		x16,x17,[x4,#7*16]
	ldp		x18,x19,[x4,#8*16]
	ldp		x20,x21,[x4,#9*16]
	ldp		x22,x23,[x4,#10*16]
	ldp		x24,x25,[x4,#11*16]
	ldp		x26,x27,[x4,#12*16]
	ldp		x28,x29,[x4,#13*16]
	stp		STi0,STi1,[x4,#0*16]
	stp		STi2,STi3,[x4,#1*16]
	mov 	x0,STi3
	ret
#endif
