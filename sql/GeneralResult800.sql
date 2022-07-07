SELECT tg.*,s.identical,s."similar",s.new,s.deleted,r.simiscore,

case 
	when r.methods_in_diff > 0 then 'True'
	else 'False'
end as sensitiveMethosDiff

, r.repetitionpermitition,r.repetitionaction,

case 
	when r.executionwithtracediff > 0 then 'True'
	else 'False'
end as traceDiff

,h.hash,v."scanDate",v.detections,v.total,

COALESCE(t.malware, 'no identify') as typeMalware,
COALESCE(n.malware, 'no identify') as nameMalware,
case 
	when e.methods_in_diff > 0 then 'True'
	else 'False'
end as useEvasiveMethods ,

case 
	when re.methods_in_diff > 0 then 'True'
	else 'False'
end as useReflectionMethods,

z.apk_size, z.dex_size, z.markets

--into public."finalGeneralCSV"


FROM public."resultAppsSimiDroidwithPermission" s
inner join public."result180GeneralResultnewVersion" r on s.app = r.app
inner join public."appsHash" h on h.app = s.app
left join public."outputTypeMalware" t on upper(t.hash) = h.hash
left join public."outputNameMalware" n on upper(n.hash) = h.hash
inner join public."outputEvadeMalware" e on s.app = e.app
inner join public."outputReflectionMalware" re on re.app = e.app
inner join public."appsTraceDistanceGeneral" tg on tg.app = s.app
inner join public."androzooInfo" z on z.sha256 = h.hash
inner join public."virusTinfo" v on v.hash = h.hash


where h.type = 'm'


