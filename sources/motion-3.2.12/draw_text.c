#include <stdio.h>
static int digit[][7] = {
	{1,1,1,1,1,1,0},
	{0,1,1,0,0,0,0},
	{1,1,0,1,1,0,1},
	{1,1,1,1,0,0,1},
	{0,1,1,0,0,1,1},
	{1,0,1,1,0,1,1},
	{1,0,1,1,1,1,1},
	{1,1,1,0,0,0,0},
	{1,1,1,1,1,1,1},
	{1,1,1,1,0,1,1} 
};

extern char patch[480];
void draw_line(unsigned char *img,int r1, int c1, int r2, int c2, int value);

void draw_digits(unsigned char *img, int i,char pos,int val)
{
	int row = 440, col = 560,len = 10;
	if(pos == 'U') col = col;
	if(pos == 'T') col = col - 20;
	if(pos == 'H') col = col - 40;
	if(pos == 'K') col = col - 60;

	if(digit[i][0])	draw_line( img, row           , col        , row           , (col+len) , val );
	if(digit[i][1]) draw_line( img, row           , (col+len)  , (row+len)     , (col+len) , val );
	if(digit[i][2]) draw_line( img, (row+len)     , (col+len ) , (row+(2*len)) , (col+len) , val );
	if(digit[i][3]) draw_line( img, (row+(2*len)) , col        , (row+(2*len)) , (col+len) , val );
	if(digit[i][4]) draw_line( img, (row+len)     , col        , (row+(2*len)) , col       , val );
	if(digit[i][5]) draw_line( img, row           , col        , (row+len)     , col       , val );
	if(digit[i][6]) draw_line( img, (row+len)     , col        , (row+len)     , (col+len) , val );
}

unsigned char* watermark(unsigned char *p,int r, int max_row, int c,int max_col)
{
	int i,j;
	int k = 0;
	for(i = r ; i < max_row; i++)
	{
		for(j = c; j < max_col; j++)
		{
			p[i * 640 + j] = patch[k];
			k++;
		}
	}
	return p;
}

void draw_line(unsigned char *img,int r1, int c1, int r2, int c2, int value)
{
	int i,j;	
	for(i = r1; i <= r2; i++)
	{
		for(j = c1; j <= c2; j++)
			img[i*640 + j] = value;
	}
}

void draw_circle(unsigned char *img ,int x, int y, int radius,int value)
{
	int i = x,j = y,diff = 0;
	int r = x + radius, c = y + radius;
	int min = 0,max = 0;

	min = (radius -1)*(radius -1);
	max = (radius +1)*(radius +1);
	for(i = 0; i <= r ; i++)
	{
		for(j = 0; j <= c; j++)
		{
			diff = ((x-i)*(x-i))+((y-j)*(y-j)); 
			if( diff >= min && diff <= max)
				img[i*640 + j] = value;
		}
	}
}

void printing_numbers(unsigned char *img, int num)
{
	int index,val;
	char pos;

	index = 0;
	while(num )
	{
		val = num % 10;
		num = num / 10;

		if(index == 0) pos = 'U';
		else if(index == 1) pos = 'T';
		else if(index == 2) pos = 'H';
		else pos = 'K';

		draw_digits(img, val, pos,255);
		index++;
	}
}

void draw_olympic_symbol(unsigned char* img, int x, int y, int radius)
{

	int i;
	draw_circle(img, x     , y     , radius ,255);
	draw_circle(img, x     , y     , radius-(radius/10) ,255);
	for(i = radius; i >= radius-(radius/10); i--)
		draw_circle(img, x     , y     , i ,255);

	draw_circle(img, x     , y+(2*radius)+((radius/10)*2) , radius ,255);
	draw_circle(img, x     , y+(2*radius)+((radius/10)*2) , radius-(radius/10) ,255);
	for(i = radius; i >= radius-(radius/10); i--)
		draw_circle(img, x     , y+(2*radius)+((radius/10)*2) , i ,255);

	draw_circle(img, x     , y+(4*radius)+((radius/10)*4) , radius ,255);
	draw_circle(img, x     , y+(4*radius)+((radius/10)*4) , radius-(radius/10) ,255);
	for(i = radius; i >= radius-(radius/10); i--)
		draw_circle(img, x     , y+(4*radius)+((radius/10)*4) , i ,255);

	draw_circle(img, x+radius  , y+radius+(radius/10)  , radius ,0);
	draw_circle(img, x+radius  , y+radius+(radius/10)  , radius-(radius/10) ,0);
	for(i = radius; i >= radius-(radius/10); i--)
		draw_circle(img, x+radius  , y+radius+(radius/10)  , i ,0);

	draw_circle(img, x+radius  , y+((radius+(radius/10))*3) , radius ,0);
	draw_circle(img, x+radius  , y+((radius+(radius/10))*3) , radius-(radius/10) ,0);
	for(i = radius; i >= radius-(radius/10); i--)
		draw_circle(img, x+radius  , y+((radius+(radius/10))*3) , i ,0);

}

void face_detection(unsigned char* img)
{
	int i = 0,j = 0,k = 0,l = 0,cunt=0;

	for(i = 0; i < 480; i++)
	{
		for(j = 0; j < 640; j++)
		{
			for(k = 0; k < 15;)
			{
				cunt = 0;
				for(l = 0; l < 32; l++)
				{
					if(img[i*640 + j] == patch[k*32 + l])
						cunt++;
					j++;
				}
				if(cunt >= 7)
				{
					k++;
					if(k >= 02)
					{
						printf("=============================================== %d %d \n",cunt,k);
						draw_circle(img, i+20, j,80,255);
						return;
					}
					j = j - 16;
					i++;

				}
				else
				{
					if((j+16) < 640)
					{
						j = j - 16;
					}
					else 
					{
						i++;
						if(i >= 480)
							return;
						j=0;
						k=0;
					}
				}
			}			
		}
	}
}

