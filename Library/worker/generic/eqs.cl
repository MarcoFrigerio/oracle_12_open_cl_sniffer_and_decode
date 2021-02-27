#define OUTSIZE 64

typedef struct {
	uchar srs[OUTSIZE];
	bool rs; // in bytes
} outbuf;


void printstrhex(__global uchar * strin,uint l,uint p){
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
	__global outbuf * result
	)
{
	uint gid = get_global_id(0);
	uint p=0;

	result[gid].rs=true;
	uint h=(gid*OUTSIZE);
	#pragma unroll OUTSIZE
	for(uint i=h;i<OUTSIZE+h;i++){
		result[gid].srs[i]=str1[i];
		printf(" %d %X ",i,result[gid].srs[i]);
		if (str1[i]!=str2[i]){
			result[gid].rs=false;
		}
	}
	printstrhex(result[gid].srs,64,gid);
}


