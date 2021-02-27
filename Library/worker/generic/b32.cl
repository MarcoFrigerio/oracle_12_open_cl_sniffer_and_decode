#define STRSIZE 32
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
	__global uchar * result,
	const unsigned int strlen 
	)
{
	uint gid = get_global_id(0);
	uint p=0;
	uchar str_rs[STRSIZE];
	uint h=(gid*strlen);
	#pragma unroll STRSIZE
	for(uint i=h;i<STRSIZE+h;i++)
		{
			str_rs[p]=str1[i];
			p++;
	}

	//printstrhex(str_rs,64,gid);
	h=(gid*STRSIZE);
	p=0;
	#pragma unroll STRSIZE
	for (uint i=h;i<STRSIZE+h;i++)
		{
			result[i]=str_rs[p];
			p++;
	}
	
}


