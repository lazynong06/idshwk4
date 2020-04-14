#create a dict of dict,{ip:{code:count,code2,count2},ip2:{code:count}}
type codeDict: table[count] of count;
type ipDict: table[addr] of codeDict;
#储存url
type urlSet: set[string];
type ipUrl: table[addr] of urlSet;

global IP:ipDict;
global URL:ipUrl;
global TenMins:interval = 10 mins;
global LastTime:time = network_time();

event http_reply(c:connection, version:string,code:count,reason:string)
{
        #将code加入到对应ip字典中
        local ip = c$http$id$orig_h;
        if(ip in IP){
                if(code in IP[ip]){
                        IP[ip][code] += 1;
                }else{
                        IP[ip][code] = 1;
                }
        }else{
                local cd:codeDict;
                IP[ip] = cd;
                IP[ip][code] = 1;
        }
        #404时储存url
        if(code==404){
        	if(ip in URL){
        	add URL[ip][c$http$uri];
        	}else{
        		URL[ip] = set(c$http$uri);
    		}
        }
        #统计判断
        local cur_T = network_time();
        if(cur_T-LastTime>=TenMins)
        {
        	LastTime = cur_T;
        	#
        	for(ip in IP)
        	{
        		if(404 in IP[ip]&&IP[ip][404]>2){
        			#响应次数和
        			local sum = 0;
        			for(d in IP[ip])
        				sum += IP[ip][d];
    				if(IP[ip][404]*1.0/sum>0.2){
    					#不同uri
    					local s = 0;
    					for(u in URL[ip])
    						s += 1;
						if(s*1.0/IP[ip][404]>0.5)
							print fmt(" %s is a scanner with %d scan attemps on %d urls", ip,sum,s);
					}
    			}
        	}
        	#清空
        	clear_table(IP);
        	clear_table(URL);
        }
}

