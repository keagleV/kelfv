#include <kelfv.h>
#include <kelfvtypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <regex.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

// TODO change in scanf %69s
#define KELFV_INPUT_CMD_MAX_LENGTH 70


#define KELFV_CMD_REGEX_COUNT 4
#define KELFV_CMD_REGEX_FILE_CMD "\\s*file\\s*[a-zA-Z_]\\s*"
#define KELFV_CMD_REGEX_HEADER_CMD "\\s*header\\s*"
#define KELFV_CMD_REGEX_SECTIONS_CMD "\\s*sections\\s*"
#define KELFV_CMD_REGEX_EXIT_CMD "\\s*exit\\s*"
#define KELFV_CMD_REGEX_HELP_CMD "\\s*?\\s*"


/**
 * Macro Functions
 */

/**
 * Checks if the file is a valid elf file
 * f16bytes: First 16 bytes
 */




//#define IS_VALID_ELF(f16bytes)({\
//        if(f16bytes[0]==0x7f && f16bytes[1]=='E' && f16bytes[2]=='L' &&f16bytes[3]=='F')\
//            1;\
//            })






/**
 * Prints the banner for the KELFV program
 */
static void
kelfv_print_banner(void){

    printf("Welcome to KELFV V0.1\n\n\n");

}






enum kelfv_cmd_regex_name{
    KELFV_CMD_REGEX_FILE_CMD_ENUM = 0,
    KELFV_CMD_REGEX_HEADER_CMD_ENUM,
    KELFV_CMD_REGEX_SECTIONS_CMD_ENUM,
    KELFV_CMD_REGEX_EXIT_CMD_ENUM,
    KELFV_CMD_REGEX_HELP_CMD_ENUM,


};





/**
 * Compiles all the regex
 * @return Arrays of compiled regexes
 */
static regex_t  *
kelfv_setup_cmd_regexes(void){

    // Allocating memory for regexes
    regex_t * regexSet = malloc ( sizeof(regex_t) * KELFV_CMD_REGEX_COUNT);

    if ( regexSet && !regcomp(&regexSet[KELFV_CMD_REGEX_FILE_CMD_ENUM],KELFV_CMD_REGEX_FILE_CMD,0) &&
             !regcomp(&regexSet[KELFV_CMD_REGEX_HEADER_CMD_ENUM],KELFV_CMD_REGEX_HEADER_CMD,0) &&
             !regcomp(&regexSet[KELFV_CMD_REGEX_EXIT_CMD_ENUM],KELFV_CMD_REGEX_EXIT_CMD,0) &&
             !regcomp(&regexSet[KELFV_CMD_REGEX_HELP_CMD_ENUM],KELFV_CMD_REGEX_HELP_CMD,0) &&
             !regcomp(&regexSet[KELFV_CMD_REGEX_SECTIONS_CMD_ENUM],KELFV_CMD_REGEX_SECTIONS_CMD,0)){

        return regexSet;
    }

    return NULL;
}


/**
 * Checks whether specified path exists and if yes, is it a regular file or not
 * @param filePath
 * @return 1 if file exists and is a regular file , else 0
 */
static u8
kelfv_is_file_valid(const u8 * filePath){

    struct stat * fileStatus = malloc(sizeof(struct stat));

    if ( stat(filePath,fileStatus)==0 && S_ISREG(fileStatus->st_mode))
        return 1;

    return 0;
}



/**
 * Returns the index'th portion of the input command based on the given delimiter
 * @param inputCmd input command
 * @param index specifies the index
 * @param delim specifies delimiter byte
 * @return the portion if successful, else NULL
 */
static u8 *
kelfv_extract_cmd_portions(const u8 * inputCmd , u8 index , u8 * delim){

    // Allocating a separate buffer and copy the inputCmd

    u8 inputCmdLength = strlen(inputCmd);

    u8 * buffer = malloc(inputCmdLength);

    strncpy(buffer,inputCmd,inputCmdLength);

    u8 * portion=NULL;

    if (index>=0) {
        portion = strtok(buffer, delim);

        index--;
    }

    for (u8 i =0 ;i<=index;i++)
        portion = strtok(NULL,delim);



    // Allocating memory for the portion
    u8 * portionBuff = malloc(strlen(portion));
    strncpy(portionBuff,portion,strlen(portion));


    free(buffer);

    return portionBuff;
}




/**
 * Extracts information stored in elf header
 * @param fp file pointer to the file
 * @param f16bytes ELF file first 16 bytes
 */
static void
kelfv_parse_elf_header(FILE * fp, const u8 * f16bytes){

    // Setting file pointer to point to the first of the file
    fseek(fp,0,SEEK_SET);


    printf("ELF ID\n");
    printf("-------------------------------------------------------------------------------------------------\n");
    printf("0x%x  0x%x  0x%x  0x%x  0x%x  0x%x  0x%x  0x%x  0x%x  0x00  0x00  0x00  0x00   0x00 | 0x00 | 0x00\n",f16bytes[0],f16bytes[1],f16bytes[2],f16bytes[3],f16bytes[EI_CLASS],f16bytes[EI_DATA],f16bytes[EI_VERSION],f16bytes[EI_OSABI],f16bytes[EI_ABIVERSION]);
    printf("0x7f    E     L     F   id[4] id[5] id[6] id[7] id[8] \n");
    printf("-------------------------------------------------------------------------------------------------\n");

    u8 * ELFClass = "unk";
    if (f16bytes[EI_CLASS] == ELFCLASS32)
        ELFClass = "32bit";
    else if (f16bytes[EI_CLASS] == ELFCLASS64)
        ELFClass="64bit";
    printf("id[4](Class): %s,    [32bit,=0x01 64bit,=0x02 unk=0xXX]\n",ELFClass );


    u8 *ELFDenc = "unk";
    if (f16bytes[EI_DATA] == ELFDATA2LSB)
        ELFDenc = "2's complement, little endian";
    else if (f16bytes[EI_DATA] == ELFDATA2MSB)
        ELFDenc="2's complement, big endian";


    printf("id[5](Data Enc): %s,   [2's complement + LittleEnd(0x01),BigEnd(0x02), unk=0xXX]\n",ELFDenc);
    printf("id[6](File Ver): %x\n",f16bytes[EI_VERSION]);

    u8 * ELFosabi = "unk";
    if (f16bytes[EI_OSABI]==ELFOSABI_NONE)
        ELFosabi= "UNIX System V ABI";
    else if (f16bytes[EI_OSABI]==ELFOSABI_HPUX)
        ELFosabi= "HP-UX";

    printf("id[7](OS/ABI): %s,    [ unix/sysV=0x00 , HP-UX=0x01 , ... ] \n",ELFosabi);


    printf("id[8](ABI Ver): %x\n",f16bytes[EI_ABIVERSION]);


    printf("\nArchitecture Metadata\n");
    printf("-------------------\n");

    u8 * ELFType = "unk";
    u8 * ELFMachine = "unk";


    // First define the bit-architecture of the file
    if (f16bytes[EI_CLASS] == ELFCLASS32){
        // 32-bit class
        Elf32_Ehdr fileElf32H;

        if ( fread(&fileElf32H,1,sizeof(Elf32_Ehdr),fp) != sizeof(Elf32_Ehdr))
            printf("[ERR] Cannot read the ELF header from the file\n");

        else{
            if(fileElf32H.e_type==ET_REL)
                ELFType="Relocatable";
            else if(fileElf32H.e_type==ET_EXEC)
                ELFType="Executable";
            else if(fileElf32H.e_type==ET_DYN)
                ELFType="Shared";
            else if(fileElf32H.e_type==ET_CORE)
                ELFType="Core";
            printf("ELF Type: %s,       [0x01=REL, 0x02=EXEC, 0x03=SHARED, 0x04=CORE, ...]\n",ELFType);



            if(fileElf32H.e_machine==EM_386)
                ELFMachine="Intel 80386";
            else if(fileElf32H.e_machine==EM_860)
                ELFMachine="Intel 80860";
            else if(fileElf32H.e_machine==EM_IAMCU)
                ELFMachine="Intel MCU";
            else if(fileElf32H.e_machine==EM_SPARC)
                ELFMachine="UN SPARC";
            else if (fileElf32H.e_machine==EM_X86_64)
                ELFMachine="AMD x86-64 architecture";
            printf("ELF Machine: %s(0x%x),       [0x02=SUN SPARC, 0x03=I80386, 0x06=Intel MCU, 0x07=I80860, ...]\n",ELFMachine,fileElf32H.e_machine);

            printf("ELF Version: 1, Current version (not important)\n");

            printf("Entry Address: 0x%x\n",fileElf32H.e_entry);

            if (fileElf32H.e_shnum) {

                printf("Sections Table Start Address: 0x%x   (%d bytes from start)\n", fileElf32H.e_shoff,
                       fileElf32H.e_shoff);

                printf("\t %d sections of %d bytes \n", fileElf32H.e_shnum, fileElf32H.e_shentsize);

                printf("Sections' names table entry index: %d\n",fileElf32H.e_shstrndx);

            } else
                printf("No sections\n");

            if (fileElf32H.e_phnum) {
                printf("Segments Table Start Address: 0x%x   (%d bytes from start)\n", fileElf32H.e_phoff,
                       fileElf32H.e_phoff);

                printf("\t %d segments of %d bytes \n", fileElf32H.e_phnum, fileElf32H.e_phentsize);
            } else
                printf("No segments\n");
        }



    }

    else if (f16bytes[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr fileElf64H;


        if ( fread(&fileElf64H,1,sizeof(Elf64_Ehdr),fp) != sizeof(Elf64_Ehdr))
            printf("[ERR] Cannot read the ELF header from the file\n");
        else{

            if(fileElf64H.e_type==ET_REL)
                ELFType="Relocatable";
            else if(fileElf64H.e_type==ET_EXEC)
                ELFType="Executable";
            else if(fileElf64H.e_type==ET_DYN)
                ELFType="Shared";
            else if(fileElf64H.e_type==ET_CORE)
                ELFType="Core";
            printf("ELF Type: %s,       [0x01=REL, 0x02=EXEC, 0x03=SHARED, 0x04=CORE, ...]\n",ELFType);


            if(fileElf64H.e_machine==EM_386)
                ELFMachine="Intel 80386";
            else if(fileElf64H.e_machine==EM_860)
                ELFMachine="Intel 80860";
            else if(fileElf64H.e_machine==EM_IAMCU)
                ELFMachine="Intel MCU";
            else if(fileElf64H.e_machine==EM_SPARC)
                ELFMachine="UN SPARC";
            else if (fileElf64H.e_machine==EM_X86_64)
                ELFMachine="AMD x86-64 architecture";

            printf("ELF Machine: %s(0x%x),       [0x02=SUN SPARC, 0x03=I80386, 0x06=Intel MCU, 0x07=I80860, ...]\n",ELFMachine,fileElf64H.e_machine);

            printf("ELF Version: 1, Current version (not important)\n");

            printf("Entry Address: 0x%x\n",fileElf64H.e_entry);

            if (fileElf64H.e_shnum) {

                printf("Sections Table Start Address: 0x%x   (%d bytes from start)\n", fileElf64H.e_shoff,
                       fileElf64H.e_shoff);

                printf("\t %d sections of %d bytes \n", fileElf64H.e_shnum, fileElf64H.e_shentsize);

                printf("Sections' names table entry index: %d\n",fileElf64H.e_shstrndx);

            } else
                printf("No sections\n");

            if (fileElf64H.e_phnum) {
                printf("Segments Table Start Address: 0x%x   (%d bytes from start)\n", fileElf64H.e_phoff,
                       fileElf64H.e_phoff);

                printf("\t %d segments of %d bytes \n", fileElf64H.e_phnum, fileElf64H.e_phentsize);
            } else
                printf("No segments\n");
        }
    }
}

/**
 * Extracts sections information
 * @param fp file pointer to the file
 * @param f16bytes ELF file first 16 bytes
 */
static void
kelfv_parse_sections(FILE * fp, const u8 * f16bytes){

    // Setting the file pointer pointing to the first of the file
    fseek(fp,0,SEEK_SET);


    printf("ELF Sections\n\n");


    if (f16bytes[EI_CLASS] == ELFCLASS32){

        // Reading ELF header
        Elf32_Ehdr elf32Ehdr;
        fread(&elf32Ehdr,1,sizeof(Elf32_Ehdr),fp);

        // Check if section headers table exist
        if (! elf32Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else{
            // printing sections

            // Seeking to the start of the section header table
            fseek(fp,elf32Ehdr.e_shoff,SEEK_SET);

            printf("Section names table index: %d \n",elf32Ehdr.e_shstrndx);

            Elf32_Shdr elf32Shdr;


            for ( u32 i=0;i<elf32Ehdr.e_shnum;i++){
                fread(&elf32Shdr,1,sizeof(Elf32_Shdr),fp);
                printf("READING\n");

            }
        }
    }
    else if (f16bytes[EI_CLASS] == ELFCLASS64){
        // Reading ELF header
        Elf64_Ehdr elf64Ehdr;
        fread(&elf64Ehdr,1,sizeof(Elf64_Ehdr),fp);

        // Check if section headers table exist
        if (! elf64Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else{
            // printing sections

            // Seeking to the start of the section header table
            fseek(fp,elf64Ehdr.e_shoff,SEEK_SET);

            printf("Section names table index: %d \n",elf64Ehdr.e_shstrndx);

            Elf64_Shdr elf64Shdr;

            for ( u32 i=0;i<elf64Ehdr.e_shnum;i++){
                fread(&elf64Shdr,1,sizeof(Elf64_Shdr),fp);
                printf("READING\n");

            }

        }
    }
    else
        printf("[ERR] Invalid ELF class 0x%x\n",f16bytes[EI_CLASS]);
}



/**
 * Prints help of the program
 */
static void
kelfv_print_help(void){

    printf("file FILENAME             Specifying filename\n");
    printf("header                    Print ELF sections\n");
    printf("?                         Print help\n");

}


/* File pointer of the specified file */
FILE * ELF_FILE_fp=NULL;

/* ELF First 16 bytes buffer */
u8 ELFFileF16Bytes[16];






/**
 * Starts the KELFV prompt
 * @param cmdRegexes regexes required for the commands
 * @return status of execution
 */
static u8
kelfv_start_prompt(regex_t * cmdRegexes){

    /* Buffer for input command */
    u8 kelfvInputCmd[KELFV_INPUT_CMD_MAX_LENGTH];

    /* Path to a file to be processed */
    u8 * filePath=NULL;


    while(1){
        printf("kelfv$ ");
        gets(kelfvInputCmd);
//        printf("%s",kelfvInputCmd);
//        exit(0);

        if (regexec(&cmdRegexes[KELFV_CMD_REGEX_FILE_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0){

            // Extracting file's path

            // Freeing previous allocated memory for file's path
            if(filePath)
                free(filePath);

            filePath= kelfv_extract_cmd_portions(kelfvInputCmd,1," ");

            if (!filePath)
                printf("[ERR] Extracting file path failed \n");
            else {

                // Checking for file status
                if (kelfv_is_file_valid(filePath) != 1)
                    printf("[ERR] file (%s) whether not exists or not a regular file\n", filePath);
                else {
                    printf("[INF] Variable 'file=' set to (%s)\n", filePath);

                    // Check if an open file exists, if yes, first close it
                    if (ELF_FILE_fp)
                        fclose(ELF_FILE_fp);

                    if ( ! (ELF_FILE_fp = fopen(filePath , "rb") ) )
                        printf("[ERR] Cannot open file (%s)! ",filePath);

                    else{
                        // Reading the first 16 bytes to determine the validation of ELF and it's type (32/64)

                        if( fread(ELFFileF16Bytes,1,16,ELF_FILE_fp) != 16 )
                            printf("[ERR] Cannot read 16 bytes from file (%s)! \n",filePath);
                        else{
                            //TODO
                            //   if (! IS_VALID_ELF(fileId))
                            if(!(ELFFileF16Bytes[0]==0x7f && ELFFileF16Bytes[1]=='E' && ELFFileF16Bytes[2]=='L' &&ELFFileF16Bytes[3]=='F')) {
                                printf("[ERR] File (%s) is not a valid ELF file, closing file\n", filePath);

                                // Closing file and make file pointer NULL to indicate invalid file
                                fclose(ELF_FILE_fp);
                                ELF_FILE_fp = NULL;
                            }
                        }
                    }
                }
            }
        }

        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_HEADER_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0){

            // First check if a file has been specified or not
            if (!ELF_FILE_fp)
                printf("[ERR] No file has been specified, use 'file FILENAME' cmd\n");
            else{

                // If it is a valid ELF file, then extract its header!
                kelfv_parse_elf_header(ELF_FILE_fp,ELFFileF16Bytes);

            }
        }

        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_HELP_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0){

            // Calling help print function
            kelfv_print_help();

        }

        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_SECTIONS_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0)

            // First check if a file has been specified or not
            if (!ELF_FILE_fp)
                printf("[ERR] No file has been specified, use 'file FILENAME' cmd\n");
            else
                kelfv_parse_sections(ELF_FILE_fp,ELFFileF16Bytes);

        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_EXIT_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0)
            return  1;

    }

}











int main(void){

    kelfv_print_banner();

    regex_t * cmdRegexes = kelfv_setup_cmd_regexes();

    if (!cmdRegexes){
        printf("[ERR] Compiling Commands Failed\n");
        return 1;
    }

    if ( kelfv_start_prompt(cmdRegexes)!=1)
        printf("[ERR] Prompt daemon stopped\n");




    return 0;
}


