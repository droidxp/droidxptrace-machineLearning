
SELECT app, 

max(method1), 
max(method2), 
max(method3), 
max(method4), 
max(method5), 
max(method6), 
max(method7), 
max(method8), 
max(method9), 
max(method10), 
max(method11), 
max(method12), 
max(method13), 
max(method14), 
max(method15), 
max(method16), 
max(method17), 
max(method18), 
max(method19), 
max(method20), 
max(method21), 
max(method22), 
max(method23), 
max(method24), 
max(method25), 
max(method26), 
max(method27), 
max(method28), 
max(method29), 
max(method30), 
max(method31), 
max(method32), 
max(method33), 
max(method34), 
max(method35), 
max(method36), 
max(method37), 
max(method38), 
max(method39), 
max(method40), 
max(method41), 
max(method42), 
max(method43), 
max(method44), 
max(method45), 
max(method46), 
max(method47), 
max(method48), 
max(method49), 
max(method50), 
max(method51), 
max(method52), 
max(method53), 
max(method54), 
max(method55), 
max(method56), 
max(method57), 
max(method58), 
max(method59), 
max(method60), 
max(method61), 
max(method62), 
max(method63), 
max(method64), 
max(method65), 
max(method66), 
max(method67), 
max(method68), 
max(method69), 
max(method70), 
max(method71), 
max(method72), 
max(method73), 
max(method74), 
max(method75), 
max(method76), 
max(method77), 
max(method78), 
max(method79), 
max(method80), 
max(method81), 
max(method82), 
max(method83), 
max(method84), 
max(method85), 
max(method86), 
max(method87), 
max(method88), 
max(method89), 
max(method90), 
max(method91), 
max(method92), 
max(method93), 
max(method94), 
max(method95), 
max(method96), 
max(method97), 
max(method98), 
max(method99), 
max(method100), 
max(method101), 
max(method102), 
max(method103), 
max(method104), 
max(method105), 
max(method106), 
max(method107), 
max(method108), 
max(method109), 
max(method110), 
max(method111), 
max(method112), 
max(method113), 
max(method114), 
max(method115), 
max(method116), 
max(method117), 
max(method118), 
max(method119), 
max(method120), 
max(method121), 
max(method122), 
max(method123), 
max(method124), 
max(method125), 
max(method126), 
max(method127), 
max(method128), 
max(method129), 
max(method130), 
max(method131), 
max(method132), 
max(method133), 
max(method134), 
max(method135), 
max(method136), 
max(method137), 
max(method138), 
max(method139), 
max(method140), 
max(method141), 
max(method142), 
max(method143), 
max(method144), 
max(method145), 
max(method146), 
max(method147), 
max(method148), 
max(method149), 
max(method150), 
max(method151), 
max(method152), 
max(method153), 
max(method154), 
max(method155), 
max(method156), 
max(method157), 
max(method158), 
max(method159), 
max(method160), 
max(method161), 
max(method162)
	
	
into public."appsTraceDistanceGeneral"

FROM public."appsTraceDistance"

group by app
order by app