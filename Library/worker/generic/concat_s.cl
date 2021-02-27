#define STRSIZE 32
#define OUTSIZE 64
void printstrhex(uchar * strin,uint l,uint p){
    //while (key_g[i]!='\0') {
    for (uint i=0;i<l;i++){
        if(i==0){printf("\n");printf(" p %d :",p);}
        printf("%X", strin[i]);
        if(i==l){printf(" %d \n",i);}
        }
}

__kernel void concat_str(
    __global uchar * str1,
    __global uchar * str2,
    __global uchar * result
    )
{
    uint gid = get_global_id(0);
	uint p=0;
	uchar str_rs[OUTSIZE];
	//printf("gid %d \n",gid);
	uint h=(gid*STRSIZE);
	#pragma unroll STRSIZE
    for(uint i=h;i<STRSIZE+h;i++)
			{
			str_rs[p]=str1[i];
			str_rs[p+STRSIZE]=str2[i];
			p++;
		}

	p=0;
		
	//if (gid==0){
	//printstrhex(str_rs,64,gid);}
	h=(gid*OUTSIZE);
	p=0;
    #pragma unroll OUTSIZE
    for (uint i=h;i<OUTSIZE+h;i++)
        {
            result[i]=str_rs[p];
            p++;
    }
	
}


