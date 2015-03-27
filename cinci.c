//BOBOC DIANA-ANDREEA GRUPA 312CA
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<math.h>
union record {
    char charptr[512];
    struct header {
            char name[100];
            char mode[8];
            char uid[8];
            char gid[8];
            char size[12];
            char mtime[12];
            char chksum[8];
            char typeflag;
            char linkname[100];
            char magic[8];
            char uname[32];
            char gname[32];
            char devmajor[8];
            char devminor[8];
    } header;
} m;
void load( char archivename[30]) 
{   FILE *f,*g,*o,*w;
    char file[512],user[512],*p,*q,aux[512],s[512];
   int nr=0;
    long sum=0;int i;
    f=fopen("usermap.txt","rt");
    g=fopen("file_ls","rt");
    o=fopen(archivename,"wt");
    if (f==NULL || g==NULL)
    {   printf("Fisiere negasite\n");
        
    }
    else
    {   while (fgets(file,512,g)!=NULL ) 
        {   
            f=fopen("usermap.txt","rt");
            p=strtok(file," \n");
            //Verificam daca linia citita contine informatii despre un fisier 
            if (p[0]=='-') {
            
                //Se calculeaza permisiunile si se retin in campul potrivit
                m.header.typeflag='0';
                m.header.mode[7]=0;
                int permission=0;
                if (p[1]=='r') permission+=4;
                if (p[2]=='w') permission+=2;
                if (p[3]=='x') permission+=1;
                snprintf(&(m.header.mode[4]),8,"%d",permission);
                permission=0;
                if (p[4]=='r') permission+=4;
                if (p[5]=='w') permission+=2;
                if (p[6]=='x') permission+=1;
                snprintf(&(m.header.mode[5]),8,"%d",permission);
                permission=0;
                if (p[7]=='r') permission+=4;
                if (p[8]=='w') permission+=2;
                if (p[9]=='x') permission+=1;
                snprintf(&(m.header.mode[6]),8,"%d",permission);
                m.header.mode[0]=m.header.mode[1]=m.header.mode[2]=m.header.mode[3]='0';
  
                //Se retine numele ownerului fisierului
                p=strtok(NULL," \n");
                p=strtok(NULL," \n");       
             
                strcpy(m.header.uname,p);

               //Se retine numele grupului din care face parte fisierul
                p=strtok(NULL," \n");
                strcpy(m.header.gname,p);
                     
                strcpy(m.header.magic,"GNUtar ");
                strcpy(m.header.devmajor,"0000000");
                strcpy(m.header.devminor,"0000000");
        
                //Se calculeaza dimensiunea fisierului si se retine     
                p=strtok(NULL," \n");             
                long x=atoll(p);
                snprintf(m.header.size,12,"%.11lo",x);

                 /* Se retine timpul existentei fisierului pentru a putea parcurge
                  linia in continuare */
                p=strtok(NULL," \n");
                p=strtok(NULL," \n");
                strcpy(aux,p);
                 
                //Se retine numele fisierului            
                p=strtok(NULL," \n");
                p=strtok(NULL," \n");                      
                strcpy(m.header.name,p);
                strcpy(m.header.linkname,p);
                // Se cauta userul in fisierul usermap.txt si se extrage UID si GID
                int find=1,i;
                while (find) {
                    fgets(user,512,f); 
                    q=strstr(user,m.header.uname);
                    if ( q ) {
                        find=0;
                        //Se calculeaza UID
                         q=strtok(user,":");
                         q=strtok(NULL,":");
                         q=strtok(NULL,":");
                         x=atoll(q);i=6;
                         snprintf(m.header.uid,8,"%.7lo",x);
          
                         //Se calculeaza GID
                         q=strtok(NULL,":");
                         x=atoll(q);i=6;                         
                         snprintf(m.header.gid,8,"%.7lo",x);
                    }
                }
                //Se calculeaza timpul existentei fisierului si se retine in header
                q=strtok(aux,":");
                x=atoll(q);
                long time=x*3600;
                q=strtok(NULL,":");
                x=atoll(q);
                time+=x*60;
                q=strtok(NULL,":");
                x=atoll(q);
                time+=x;
                snprintf(m.header.mtime,12,"%.11lo",time);
                 
                //Se calculeaza checksum-ul
       
                sum=0;i=0;
                while (m.header.name[i]!=0) {
                    sum+=m.header.name[i];
                    i++;
                }
                i=0;
                while (m.header.mode[i]!=0) {
                   sum+=m.header.mode[i];
                    i++;
                } 
                i=0;
                while (m.header.uid[i]!=0) {
                    sum+=m.header.uid[i];
                    i++;
                }   
                i=0;
                while (m.header.gid[i]!=0) {
                    sum+=m.header.gid[i];
                    i++;
                }
                i=0;
                while (m.header.size[i]!=0) {
                    sum+=m.header.size[i];
                    i++;
                }
                i=0;
                while (m.header.mtime[i]!=0) {
                    sum+=m.header.mtime[i];
                    i++;
                }
                sum+=m.header.typeflag;
                i=0;
                while (m.header.linkname[i]!=0) {
                    sum+=m.header.linkname[i];
                    i++;
                }
                i=0;
                while (m.header.magic[i]!=0) {
                    sum+=m.header.magic[i];
                    i++;
                }
                i=0;
                while (m.header.uname[i]!=0) {
                    sum+=m.header.uname[i];
                    i++;
                }
                i=0;
                while (m.header.gname[i]!=0) {
                    sum+=m.header.gname[i];
                    i++;
                }
                i=0;
                while (m.header.devmajor[i]!=0) {
                    sum+=m.header.devmajor[i];
                    i++;
                }
                i=0;
                while (m.header.devminor[i]!=0) {
                    sum+=m.header.devminor[i];
                    i++;
                }
                sum+=8*(int)(' ');
                snprintf(m.header.chksum,8,"%.6lo",sum);        
            }
         //Se scrie header-ul in arhiva
         fwrite (&m,sizeof (union record),1,o);         
         //Se scrie in arhiva continutul fisierului arhivat
         w=fopen(m.header.name,"rt");
         if (w) {
            while (fgets(s,512,w) != NULL ) {                          
                fprintf(o,"%s",s);
            }
         //Se completeaza cu '\0' restul de spatiu ramas din bloc pentru a fi complet   
         fseek(w,0,SEEK_END);
         nr=ftell(w);        
         for (i=nr%512;i<=511;i++)
            fprintf(o,"%c",'\0');
         }
         fclose(w);
         fclose(f);
         }
    }    
    fclose(o);
    fclose(g);
}

void list (char archivename[30]) {
    FILE *o;int i,decimal,octal;
    union record aux;
    o=fopen(archivename,"rt");
    if (o) {
    while (fread(&aux,sizeof(union record),1,o) ) {
        /* Dupa ce header-ul primului fisier arhivat a fost citit,se poate afisa
           numele acestui fisier */
        printf("%s\n",aux.header.name);
        // Se retine dimensiunea fisierului si se transforma in zecimal
        octal=atoi (aux.header.size);
        decimal=0;i=0;
        while(octal!=0)
        {
            decimal = decimal + (octal % 10) * pow(8,i++);
            octal = octal/10;
        }
        /* Daca continutul fisierului a reusit sa fie cuprins intr-un nr de blocuri
            complete,se trece pur si simplu peste caracterele reprezentand continutul
            fisierului, daca nu se trece si peste caracterele '\0' folosite pentru
            a umple complet blocurile */
        if (decimal % 512!=0)
        {
            fseek(o,(decimal/512 + 1)*512 , SEEK_CUR);
        }
        else {
                fseek(o,decimal,SEEK_CUR); 
             }   

    }
    fclose(o); 
    }
}

void get (char archivename[30],char filename[30]) {
    FILE *o;
    int i,nr=0,decimal,octal;
    char s[513];
    union record aux;
    o=fopen(archivename,"rt");
    if (o) {
    while (fread(&aux,sizeof(union record),1,o) ) {
        /* Dupa ce a fost retinut header-ul fisierului curent,se transforma 
            dimensiunea fisierului in zecimal */    
        octal=atoi (aux.header.size);
        decimal=0;i=0;
        while(octal!=0){
             decimal = decimal + (octal % 10) * pow(8,i++);
             octal = octal/10;
        }
        /* Daca fisierul curent este cel cautat i se afiseaza continutul si se
            iese din functie */
        if (strcmp(aux.header.name,filename) == 0) {
            while (nr<decimal){
                fgets(s,512,o);
                printf("%s",s);
                nr+=strlen(s);
            }
            fclose(o);
            return ;
        }
        /* Daca fisierul curent nu este cel cautat, se trece peste blocurile ce
            reprezinta continutul acestuia,inclusiv peste caracterele '\0' de
            umplutura */
        if (decimal % 512!=0){
            fseek(o,(decimal/512 + 1)*512 , SEEK_CUR);
        }
        else {
            fseek(o,decimal,SEEK_CUR);
        
        }   
    }
    fclose(o); 
    }
}

int main () {
    char s[50],*command,*archivename,*filename;
    fgets(s,512,stdin);
    command=strtok(s," \n");
    while ( strcmp(command,"quit") != 0) {
        
        if (strcmp(command,"load")==0) {
            archivename=strtok(NULL," \n");
            load (archivename);
        }
            if ( strcmp(command,"list") == 0) 
        {   archivename=strtok(NULL," \n");
            list(archivename);
        }
        
        if ( strcmp(command,"get") == 0)
        {   archivename=strtok(NULL," \n");
            filename=strtok(NULL," \n");
            get(archivename,filename);
        }
       
        fgets(s,512,stdin);
        command=strtok(s," \n");
    }
return 0;
}
