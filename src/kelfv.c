#include <kelfv.h>





// TODO change in scanf %69s
#define KELFV_INPUT_CMD_MAX_LENGTH 70


#define KELFV_CMD_REGEX_COUNT 10
#define KELFV_CMD_REGEX_FILE_CMD "\\s*file\\s*[a-zA-Z_]\\s*"
#define KELFV_CMD_REGEX_HEADER_CMD "\\s*header\\s*"
#define KELFV_CMD_REGEX_SECTIONS_CMD "\\s*sections\\s*"
#define KELFV_CMD_REGEX_SYMBOLS_CMD "\\s*symbols\\s*"
#define KELFV_CMD_REGEX_SEGMENTS_CMD "\\s*segments\\s*"

#define KELFV_CMD_REGEX_CLOSE_FILE_CMD "\\s*close\\s*"
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
    KELFV_CMD_REGEX_SYMBOLS_CMD_ENUM,
    KELFV_CMD_REGEX_SEGMENTS_CMD_ENUM,
    KELFV_CMD_REGEX_CLOSE_FILE_CMD_ENUM,
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
             !regcomp(&regexSet[KELFV_CMD_REGEX_SECTIONS_CMD_ENUM],KELFV_CMD_REGEX_SECTIONS_CMD,0) &&
             !regcomp(&regexSet[KELFV_CMD_REGEX_SYMBOLS_CMD_ENUM],KELFV_CMD_REGEX_SYMBOLS_CMD,0) &&
             !regcomp(&regexSet[KELFV_CMD_REGEX_CLOSE_FILE_CMD_ENUM],KELFV_CMD_REGEX_CLOSE_FILE_CMD,0) &&
            !regcomp(&regexSet[KELFV_CMD_REGEX_SEGMENTS_CMD_ENUM],KELFV_CMD_REGEX_SEGMENTS_CMD,0)){

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



//TODO Performance
/**
 * This function resolves the section's type name based on the given numeric type
 * @param sectionType Numeric value of the section's type
 * @return Section Type's string
 */
static u8 *
kelfv_resolve_section_type(u32 sectionType){

    if (sectionType==SHT_NULL)
        return "NULL";
    else if (sectionType==SHT_PROGBITS)
        return "PROGBITS";
    else if (sectionType==SHT_SYMTAB)
        return "SYMTAB";
    else if (sectionType==SHT_STRTAB)
        return "STRTAB";
    else if (sectionType==SHT_REL)
        return "RELA";
    else if (sectionType==SHT_HASH)
        return "HASH";
    else if (sectionType==SHT_DYNAMIC)
        return "DYNAMIC";
    else if (sectionType==SHT_NOTE)
        return "NOTE";
    else if (sectionType==SHT_NOBITS)
        return "NO-BITS";
    else if (sectionType==SHT_SHLIB)
        return "SHLIB";
    else if (sectionType==SHT_DYNSYM)
        return "DYNSYM";
    else if (sectionType==SHT_INIT_ARRAY)
        return "INIT_ARRAY";
    else if (sectionType==SHT_FINI_ARRAY)
        return "FINI_ARRAY";
    else if (sectionType==SHT_PREINIT_ARRAY)
        return "PREINIT_ARRAY";
    else if (sectionType==SHT_GROUP)
        return "GROUP";
    else if (sectionType==SHT_SYMTAB_SHNDX)
        return "SYMTAB_SHNDX";
    else if (sectionType==SHT_NUM)
        return "NUM";
    else if (sectionType==SHT_LOOS)
        return "LOOS";
    else if (sectionType==SHT_GNU_ATTRIBUTES)
        return "GNU_ATTR";
    else if (sectionType==SHT_GNU_HASH)
        return "GNU_HASH";
    else if (sectionType==SHT_GNU_LIBLIST)
        return "GNU_LIBLIST";
    else if (sectionType==SHT_CHECKSUM)
        return "CHECKSUM";
    else if (sectionType==SHT_SUNW_move)
        return "SUN_MOVE";
    else if (sectionType==SHT_SUNW_COMDAT)
        return "SUM_COMDAT";
    else if (sectionType==SHT_SUNW_syminfo)
        return "SUN_SYMINFO";
    else if (sectionType==SHT_GNU_verdef)
        return "GNU_VERDEF";
    else if (sectionType==SHT_GNU_verneed)
        return "GNU_VERNEED";
    else if (sectionType==SHT_GNU_versym)
        return "GNU_VERSYM";
    else if (sectionType<= SHT_HIOS)
        return "OS_SPEC";
    else if ((sectionType >= SHT_LOPROC) && (sectionType <= SHT_HIPROC) )
        return "PROC_SPEC";
    else if ((sectionType >= SHT_LOUSER) && (sectionType <= 0x8fffffff) )
        return "APP_SPEC";
    else
        return "UNKNOWN";

}


/**
 * This function resolves the section's flag based on the given numeric flag
 * @param sectionFlag Numeric value of the section's flag
 * @return Flag's string
 */
static void
kelfv_resolve_section_flag(u32 sectionFlag, u8 * sectionFlags){

    bzero(sectionFlags,16);
    u8 flagIndex=0;

    if (sectionFlag == SHF_MASKOS)
        sectionFlags[flagIndex]='O';
    else if (sectionFlag == SHF_MASKPROC)
        sectionFlags[flagIndex]='P';
    else {
        if (sectionFlag & SHF_ALLOC)
            sectionFlags[flagIndex++] = 'A';
        if (sectionFlag & SHF_WRITE)
            sectionFlags[flagIndex++] = 'W';
        if (sectionFlag & SHF_EXECINSTR)
            sectionFlags[flagIndex++] = 'X';
        if (sectionFlag & SHF_MERGE)
            sectionFlags[flagIndex++] = 'M';
        if (sectionFlag & SHF_STRINGS)
            sectionFlags[flagIndex++] = 'S';
        if (sectionFlag & SHF_INFO_LINK)
            sectionFlags[flagIndex++] = 'I';
        if (sectionFlag & SHF_LINK_ORDER)
            sectionFlags[flagIndex++] = 'L';
        if (sectionFlag & SHF_OS_NONCONFORMING)
            sectionFlags[flagIndex++] = 'N';
        if (sectionFlag & SHF_GROUP)
            sectionFlags[flagIndex++] = 'G';
        if (sectionFlag & SHF_TLS)
            sectionFlags[flagIndex++] = 'T';
        if (sectionFlag & SHF_COMPRESSED)
            sectionFlags[flagIndex++] = 'C';
        if (sectionFlag & SHF_EXCLUDE)
            sectionFlags[flagIndex++] = 'E';
        if (sectionFlag & SHF_ORDERED)
            sectionFlags[flagIndex++] = 'R';
    }

}


/**
 * This function resolves symbol's type and binding
 * @param symbolInfo Info member of the symbol entry
 * @param symbolType A buffer to write type into it
 * @param typeLen Size of the buffer for the type
 * @param symbolBinding A buffer to write binding into it
 * @param bindingLen Size of the buffer for the binding
 */
static void
kelfv_resolve_symbol_type_binding(u8 symbolInfo , u8 * symbolType, u8 typeLen , u8 * symbolBinding, u8 bindingLen){

    u16 symbolTypeNumeric = symbolInfo & 0xf;

    u16 symbolBindingNumeric = symbolInfo >> 4;


    /* Zeroing out the buffers */
    bzero(symbolType,typeLen);
    bzero(symbolBinding, bindingLen);

    if (symbolTypeNumeric==STT_NOTYPE)
        strcpy(symbolType,"No-Type");
    else if (symbolTypeNumeric==STT_OBJECT)
        strcpy(symbolType,"Object");
    else if (symbolTypeNumeric==STT_FUNC)
        strcpy(symbolType,"Function");
    else if (symbolTypeNumeric==STT_SECTION)
        strcpy(symbolType,"Section");
    else if (symbolTypeNumeric==STT_FILE)
        strcpy(symbolType,"File");
    else if (symbolTypeNumeric==STT_COMMON)
        strcpy(symbolType,"Common");
    else if (symbolTypeNumeric==STT_TLS)
        strcpy(symbolType,"TLS");
    else if (symbolTypeNumeric==STT_LOOS)
        strcpy(symbolType,"LOOS");
    else
        strcpy(symbolType,"OS-SPEC");




    if (symbolBindingNumeric==STB_LOCAL)
        strcpy(symbolBinding,"LOCAL");
    else if (symbolBindingNumeric==STB_GLOBAL)
        strcpy(symbolBinding,"GLOBAL");
    else if (symbolBindingNumeric==STB_WEAK)
        strcpy(symbolBinding,"WEAK");
    else if (symbolBindingNumeric==STB_LOOS)
        strcpy(symbolBinding,"LOOS");
    else
        strcpy(symbolBinding,"OS-SPEC");




}






/**
 * Extracts sections information
 * @param fp File pointer to the file
 * @param f16bytes ELF file first 16 bytes
 */
static void
kelfv_print_sections(FILE * fp, const u8 * f16bytes){

    // Setting the file pointer pointing to the first of the file
    fseek(fp,0,SEEK_SET);

    printf("------- ELF SECTIONS -------\n\n");

    printf("Flags: \n");
    printf("(A)[Alloc] (W)[Write] (X)[Exec] (M)[Merge] (S)[Strings]\n");
    printf("(I)[Info Link] (L)[Link Order] (N)[OS-Nonconforming] (G)[Group] (T)[TLS]\n");
    printf("(C)[Compressed] (E)[Excluded] (R)[Required Special Ordering]\n");
    printf("(O)[OS-MASK] (P)[Processor-MASK]\n");
    printf("-------------------------------------------------------------\n");


    if (f16bytes[EI_CLASS] == ELFCLASS32){

        // Reading ELF header
        Elf32_Ehdr elf32Ehdr;
        fread(&elf32Ehdr,1,sizeof(Elf32_Ehdr),fp);

        // Check if section headers table exist
        if (! elf32Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else{
            /* printing sections */

            /*
             * Seeking to the start of the section names.
             */
            fseek(fp,elf32Ehdr.e_shoff + elf32Ehdr.e_shentsize * elf32Ehdr.e_shstrndx ,SEEK_SET);


            // Reading the section header string table entry
            Elf32_Shdr elf32Shdr;
            fread(&elf32Shdr,1,sizeof(elf32Shdr),fp);

            /*
             * Allocating dynamic memory for the section header strings table
             * based on the total size of the section
             */
            u8 * shStrings = malloc(elf32Shdr.sh_size);

            if (!shStrings)
                printf("[ERR] Cannot allocate memory for header names\n");
            else{

                // Seek to the section header strings by using the offset of the entry
                fseek(fp,elf32Shdr.sh_offset ,SEEK_SET);


                // Reading the strings into the buffer allocated for the names
                fread(shStrings,1,elf32Shdr.sh_size ,fp);


                // Seeking to the start of the section header table
                fseek(fp,elf32Ehdr.e_shoff,SEEK_SET);


                printf("%-25s%-10s%-10s%-10s\n%-25s%-10s-10s-10s\n", "Name", "Type", "Flags", "Addr", "Offset","Size","Link","Info");

                // Allocating memory for section's flag
                u8 sectionFlags[16];

                for ( u32 i=0;i<elf32Ehdr.e_shnum;i++){
                    fread(&elf32Shdr,1,sizeof(elf32Shdr),fp);
                    /*
                     * Note for the string name. the sh_name is the offset which should be
                     * added to the string table start address
                    */

                    // Resolving the section's flags
                    kelfv_resolve_section_flag(elf32Shdr.sh_flags,sectionFlags);

                    printf("%-15s%-10s%-10s[A] 0x%-10llx[O] \n0x%-25llx[S] 0x%-10llx [AA] 0x%-10llx [ES] 0x%-10llx [L] %-10lli [I] %-10lli\n\n", shStrings + elf32Shdr.sh_name ,kelfv_resolve_section_type(elf32Shdr.sh_type),sectionFlags,elf32Shdr.sh_addr,elf32Shdr.sh_offset,elf32Shdr.sh_size,elf32Shdr.sh_size,elf32Shdr.sh_addralign,elf32Shdr.sh_entsize,elf32Shdr.sh_link,elf32Shdr.sh_info);

                }

                free(shStrings);


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
            /* printing sections */

            /*
             * Seeking to the start of the section names.
             */
            fseek(fp,elf64Ehdr.e_shoff + elf64Ehdr.e_shentsize * elf64Ehdr.e_shstrndx ,SEEK_SET);


            // Reading the section header string table entry
            Elf64_Shdr elf64Shdr;
            fread(&elf64Shdr,1,sizeof(elf64Shdr),fp);

            /*
             * Allocating dynamic memory for the section header strings table
             * based on the total size of the section
             */
            u8 * shStrings = malloc(elf64Shdr.sh_size);

            if (!shStrings)
                printf("[ERR] Cannot allocate memory for header names\n");
            else{

                // Seek to the section header strings by using the offset of the entry
                fseek(fp,elf64Shdr.sh_offset ,SEEK_SET);


                // Reading the strings into the buffer allocated for the names
                fread(shStrings,1,elf64Shdr.sh_size ,fp);


                // Seeking to the start of the section header table
                fseek(fp,elf64Ehdr.e_shoff,SEEK_SET);


                printf("%-25s%-10s%-10s%-10s\n%-25s%-10s-10s-10s\n", "Name", "Type", "Flags", "Addr", "Offset","Size","Link","Info");

                // Allocating memory for section's flag
                u8 sectionFlags[16];

                for ( u32 i=0;i<elf64Ehdr.e_shnum;i++){
                    fread(&elf64Shdr,1,sizeof(Elf64_Shdr),fp);
                    /*
                     * Note for the string name. the sh_name is the offset which should be
                     * added to the string table start address
                    */

                    // Resolving the section's flags
                    kelfv_resolve_section_flag(elf64Shdr.sh_flags,sectionFlags);

                    printf("%-15s%-10s%-10s[A] 0x%-10llx[O] \n0x%-25llx[S] 0x%-10llx [AA] 0x%-10llx [ES] 0x%-10llx [L] %-10lli [I] %-10lli\n\n", shStrings + elf64Shdr.sh_name ,kelfv_resolve_section_type(elf64Shdr.sh_type),sectionFlags,elf64Shdr.sh_addr,elf64Shdr.sh_offset,elf64Shdr.sh_size,elf64Shdr.sh_size,elf64Shdr.sh_addralign,elf64Shdr.sh_entsize,elf64Shdr.sh_link,elf64Shdr.sh_info);

                }

                free(shStrings);

            }

        }

    }

    else
        printf("[ERR] Invalid ELF class 0x%x\n",f16bytes[EI_CLASS]);
}



/**
 * This function will resolve the st_other field of symbol entry
 * @param symbolOtherMem Symbol's st_other value
 * @param symbolOther   Buffer to copy the string to
 * @param len   length of the allocated buffer
 */
static void
kelfv_resolve_symbol_other(u8 symbolOtherMem , u8 * symbolOther , u8 len){

    // Zeroing out the buffer
    bzero(symbolOther , len);

    symbolOtherMem &= 0x03;

    if (symbolOtherMem == STV_DEFAULT)
        strcpy(symbolOther,"Default");
    else if (symbolOtherMem == STV_INTERNAL)
        strcpy(symbolOther,"Internal");
    else if (symbolOtherMem == STV_HIDDEN)
        strcpy(symbolOther,"Hidden");
    else if (symbolOtherMem == STV_PROTECTED)
        strcpy(symbolOther,"Protected");
    else
        strcpy(symbolOther,"Unknown");

}



/**
 * This function prints symbols of each section that is of symtab type
 * @param fp File pointer to the file
 * @param f16bytes ELF file first 16 bytes
 */
static void
kelfv_print_symbols(FILE * fp , const u8 * f16bytes){


    // Setting the file pointer pointing to the first of the file
    fseek(fp,0,SEEK_SET);

    if (f16bytes[EI_CLASS] == ELFCLASS32){



        // Reading ELF header
        Elf32_Ehdr elf32Ehdr;
        fread(&elf32Ehdr,1,sizeof(Elf32_Ehdr),fp);

        // Check if section headers table exist
        if (! elf32Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else {

            /*
            * Seeking to the start of the section names.
            */
            fseek(fp, elf32Ehdr.e_shoff + elf32Ehdr.e_shentsize * elf32Ehdr.e_shstrndx, SEEK_SET);


            // Reading the section header string table entry
            Elf32_Shdr elf32Shdr;
            fread(&elf32Shdr, 1, sizeof(Elf32_Shdr), fp);

            /*
             * Allocating dynamic memory for the section header strings table
             * based on the total size of the section
             */
            u8 *shStrings = malloc(elf32Shdr.sh_size);

            if (!shStrings)
                printf("[ERR] Cannot allocate memory for header names\n");
            else {

                // Seek to the section header strings by using the offset of the entry
                fseek(fp, elf32Shdr.sh_offset, SEEK_SET);


                // Reading the strings into the buffer allocated for the names
                fread(shStrings, 1, elf32Shdr.sh_size, fp);


                // Looking for sections that are type of symbol table

                // Seeking to the start of the sections table
                fseek(fp, elf32Ehdr.e_shoff, SEEK_SET);


                for (u32 i = 0; i < elf32Ehdr.e_shnum; i++) {

                    fread(&elf32Shdr, 1, sizeof(Elf32_Shdr), fp);

                    if (elf32Shdr.sh_type == SHT_SYMTAB) {

                        printf("\nSymbols of section '%s' are: \n",shStrings+elf32Shdr.sh_name);
                        printf("-------------------------------\n");


                        /* Names of symbols are in string table section */

                        // First reading strtab section
                        Elf32_Shdr strtabSecHeader;

                        // Seeking to strtab section entry, link member contains the
                        // index of strtab.
                        fseek(fp,elf32Ehdr.e_shoff + elf32Ehdr.e_shentsize*elf32Shdr.sh_link ,SEEK_SET);
                        fread(&strtabSecHeader,1,sizeof(Elf32_Shdr),fp);

                        // Reading symbols names into a buffer
                        u8 * symbolsNames = malloc(strtabSecHeader.sh_size);
                        fseek(fp,strtabSecHeader.sh_offset,SEEK_SET);
                        fread(symbolsNames,1,strtabSecHeader.sh_size,fp);


                        // Seeking to the symbol table of the found section
                        fseek(fp,elf32Shdr.sh_offset,SEEK_SET);

                        // Symbol entry
                        Elf32_Sym elf32Sym;
                        printf("%-10s%-10s%-15s%-15s%-25s%-10s\n", "Value", "Size","Type","Binding","Index","Name");

                        u8 symbolBinding[10];
                        u8 symbolType[10];
                        u8 symbolOther[10];

                        // Number of symbols is total size divided by entry size
                        for ( u32 i=0; i< elf32Shdr.sh_size / elf32Shdr.sh_entsize ;i++){

                            fread(&elf32Sym,1,sizeof(Elf32_Sym),fp);

                            kelfv_resolve_symbol_type_binding(elf32Sym.st_info,symbolType,10,symbolBinding,10);

                            kelfv_resolve_symbol_other(elf32Sym.st_other,symbolOther,10);

                            printf("0x%-10x0x%-10x%-10s%-10s%-10d%-10s%-25s\n",elf32Sym.st_value,elf32Sym.st_size,symbolType,symbolBinding,elf32Sym.st_shndx,symbolOther,symbolsNames + elf32Sym.st_name);
                        }

                        // Freeing allocated memory
                        free(symbolsNames);
                    }
                }
            }
        }

    }

    else if (f16bytes[EI_CLASS]== ELFCLASS64){

        // Reading ELF header
        Elf64_Ehdr elf64Ehdr;
        fread(&elf64Ehdr,1,sizeof(Elf64_Ehdr),fp);

        // Check if section headers table exist
        if (! elf64Ehdr.e_shnum)
            printf("[INFO] No sections exist in this file\n");
        else {

            /*
            * Seeking to the start of the section names.
            */
            fseek(fp, elf64Ehdr.e_shoff + elf64Ehdr.e_shentsize * elf64Ehdr.e_shstrndx, SEEK_SET);


            // Reading the section header string table entry
            Elf64_Shdr elf64Shdr;
            fread(&elf64Shdr, 1, sizeof(elf64Shdr), fp);

            /*
             * Allocating dynamic memory for the section header strings table
             * based on the total size of the section
             */
            u8 *shStrings = malloc(elf64Shdr.sh_size);

            if (!shStrings)
                printf("[ERR] Cannot allocate memory for header names\n");
            else {

                // Seek to the section header strings by using the offset of the entry
                fseek(fp, elf64Shdr.sh_offset, SEEK_SET);


                // Reading the strings into the buffer allocated for the names
                fread(shStrings, 1, elf64Shdr.sh_size, fp);


                // Looking for sections that are type of symbol table

                // Seeking to the start of the sections table
                fseek(fp, elf64Ehdr.e_shoff, SEEK_SET);


                for (u32 i = 0; i < elf64Ehdr.e_shnum; i++) {

                    fread(&elf64Shdr, 1, sizeof(Elf64_Shdr), fp);

                    if (elf64Shdr.sh_type == SHT_SYMTAB) {
                        //TODO, index of symbols
                        printf("\nSymbols of section '%s' are: \n",shStrings+elf64Shdr.sh_name);
                        printf("-------------------------------\n");


                        /* Names of symbols are in string table section */

                        // First reading strtab section
                        Elf64_Shdr strtabSecHeader;

                        // Seeking to strtab section entry, link member contains the
                        // index of strtab.
                        fseek(fp,elf64Ehdr.e_shoff + elf64Ehdr.e_shentsize*elf64Shdr.sh_link ,SEEK_SET);
                        fread(&strtabSecHeader,1,sizeof(Elf64_Shdr),fp);

                        // Reading symbols names into a buffer
                        u8 * symbolsNames = malloc(strtabSecHeader.sh_size);
                        fseek(fp,strtabSecHeader.sh_offset,SEEK_SET);
                        fread(symbolsNames,1,strtabSecHeader.sh_size,fp);


                        // Seeking to the symbol table of the found section
                        fseek(fp,elf64Shdr.sh_offset,SEEK_SET);

                        // Symbol entry
                        Elf64_Sym elf64Sym;
                        printf("%-10s%-10s%-15s%-15s%-25s%-10s%-10s\n", "Value", "Size","Type","Binding","Index","Visibility","Name");

                        u8 symbolBinding[10];
                        u8 symbolType[10];
                        u8 symbolOther[10];

                        // Number of symbols is total size divided by entry size
                        for ( u32 i=0; i< elf64Shdr.sh_size / elf64Shdr.sh_entsize ;i++){

                            fread(&elf64Sym,1,sizeof(Elf64_Sym),fp);

                            kelfv_resolve_symbol_type_binding(elf64Sym.st_info,symbolType,10,symbolBinding,10);
                            kelfv_resolve_symbol_other(elf64Sym.st_other,symbolOther,10);

                            printf("0x%-10x0x%-10x%-10s%-10s%-10d%-10s%-25s\n",elf64Sym.st_value,elf64Sym.st_size,symbolType,symbolBinding,elf64Sym.st_shndx,symbolOther,symbolsNames + elf64Sym.st_name);
                        }

                        // Freeing allocated memory
                        free(symbolsNames);
                    }
                }
            }
        }
    }

    else
        printf("[ERR] Invalid ELF class 0x%x\n",f16bytes[EI_CLASS]);

}


/**
 * This function resolves the segment type string
 * @param segmentType Numeric value of the segment's type
 * @param segmentTypeStr A buffer to write string to it
 * @param len The length of the buffer
 */
static void
kelfv_resolve_segment_type(u32 segmentType , u8 * segmentTypeStr, u8 len){

    // Zeroing out the buffer
    bzero(segmentTypeStr,len);

    if (segmentType== PT_NULL)
        strcpy(segmentTypeStr,"NULL");
    else  if (segmentType== PT_LOAD)
        strcpy(segmentTypeStr,"LOAD");
    else  if (segmentType== PT_DYNAMIC)
        strcpy(segmentTypeStr,"DYN");
    else  if (segmentType== PT_INTERP)
        strcpy(segmentTypeStr,"INTERP");
    else  if (segmentType== PT_NOTE)
        strcpy(segmentTypeStr,"NOTE");
    else  if (segmentType== PT_SHLIB)
        strcpy(segmentTypeStr,"SHLIB");
    else  if (segmentType== PT_PHDR)
        strcpy(segmentTypeStr,"PHDR");
    else if (segmentType== PT_GNU_EH_FRAME)
        strcpy(segmentTypeStr,"GNU-FRAME");
    else if (segmentType== PT_GNU_STACK)
        strcpy(segmentTypeStr,"GNU-STACK");
    else if (segmentType== PT_GNU_RELRO)
        strcpy(segmentTypeStr,"GNU-RELRO");


    else if (segmentType>= 0x70000000 && segmentType <=0x7fffffff)
        strcpy(segmentTypeStr,"OS-SPEC");
    else
        strcpy(segmentTypeStr,"UNK");


}


/**
 * This function resolves the flags for the segments
 * @param segmentFlag Numeric value of the segment's flag
 * @param segmentFlagStr A buffer to write string into it
 * @param len Length of the buffer
 */
static void
kelfv_resolve_segment_flag(u32 segmentFlag , u8 * segmentFlagStr , u8 len){

    // Zeroing out the buffer
    bzero(segmentFlagStr,len);

    // String index to write flags
    u8 index=0;

    if (segmentFlag&PF_R)
        segmentFlagStr[index++]='R';
    if (segmentFlag & PF_W)
        segmentFlagStr[index++]='W';
    if (segmentFlag&PF_X)
        segmentFlagStr[index++]='X';

}


static void
kelfv_print_segments(FILE * fp , const u8 * f16bytes){

    // Setting the file pointer pointing to the first of the file
    fseek(fp,0,SEEK_SET);

    if (f16bytes[EI_CLASS] == ELFCLASS32) {

        // Reading ELF header
        Elf32_Ehdr elf32Ehdr;
        fread(&elf32Ehdr,1,sizeof(Elf32_Ehdr),fp);

        // Check if segment headers table exist
        if (! elf32Ehdr.e_phnum )
            printf("[INFO] No segments exist in this file\n");
        else {
            // Seeking to the segments table
            fseek(fp, elf32Ehdr.e_phoff , SEEK_SET);

            // Reading segments
            Elf32_Phdr elf32Phdr;
            printf("%-10s%-10s%-15s%-15s%-15s%-25s%-10s%-10s\n", "Type", "Offset","VirAddr","PhyAddr","fSize","mSize","Flags","Align");

            u8 segmentType[10];
            u8 segmentFlag[10];

            for ( u32 i=0 ; i<elf32Ehdr.e_phnum ; i++ ){

                fread(&elf32Phdr,1,sizeof(Elf32_Phdr),fp);

                kelfv_resolve_segment_type(elf32Phdr.p_type,segmentType,10);
                kelfv_resolve_segment_flag(elf32Phdr.p_flags,segmentFlag,10);

                printf("%-10s0x%-10x0x%-15x0x%-15x%-15d%-25d%-10s0x%-10x\n", segmentType,elf32Phdr.p_offset,elf32Phdr.p_vaddr,elf32Phdr.p_paddr,elf32Phdr.p_filesz,elf32Phdr.p_memsz,segmentFlag,elf32Phdr.p_align);

            }


        }

    }
    else if (f16bytes[EI_CLASS] == ELFCLASS64){

        // Reading ELF header
        Elf64_Ehdr elf64Ehdr;
        fread(&elf64Ehdr,1,sizeof(Elf64_Ehdr),fp);

        // Check if segment headers table exist
        if (! elf64Ehdr.e_phnum )
            printf("[INFO] No segments exist in this file\n");
        else {
            // Seeking to the segments table
            fseek(fp, elf64Ehdr.e_phoff , SEEK_SET);

            // Reading segments
            Elf64_Phdr elf64Phdr;
            printf("%-10s%-10s%-15s%-15s%-15s%-25s%-10s%-10s\n", "Type", "Offset","VirAddr","PhyAddr","fSize","mSize","Flags","Align");

            u8 segmentType[10];
            u8 segmentFlag[10];

            for ( u32 i=0 ; i<elf64Ehdr.e_phnum ; i++ ){

                fread(&elf64Phdr,1,sizeof(Elf64_Phdr),fp);

                kelfv_resolve_segment_type(elf64Phdr.p_type,segmentType,10);
                kelfv_resolve_segment_flag(elf64Phdr.p_flags,segmentFlag,10);

                printf("%-10s0x%-10x0x%-15x0x%-15x%-15d%-25d%-10s0x%-10x\n", segmentType,elf64Phdr.p_offset,elf64Phdr.p_vaddr,elf64Phdr.p_paddr,elf64Phdr.p_filesz,elf64Phdr.p_memsz,segmentFlag,elf64Phdr.p_align);

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
    printf("header                    Print ELF header\n");
    printf("sections                  Print ELF sections\n");
    printf("symbols                   Print ELF symbols\n");
    printf("close                     Close specified file\n");
    printf("exit                      Exit kelfv\n");

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

        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_SECTIONS_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0) {

            // First check if a file has been specified or not
            if (!ELF_FILE_fp)
                printf("[ERR] No file has been specified, use 'file FILENAME' cmd\n");
            else
                kelfv_print_sections(ELF_FILE_fp, ELFFileF16Bytes);
        }

        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_SEGMENTS_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0) {

            // First check if a file has been specified or not
            if (!ELF_FILE_fp)
                printf("[ERR] No file has been specified, use 'file FILENAME' cmd\n");
            else
                kelfv_print_segments(ELF_FILE_fp, ELFFileF16Bytes);
        }

        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_SYMBOLS_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0){

            // First check if a file has been specified or not
            if (!ELF_FILE_fp)
                printf("[ERR] No file has been specified, use 'file FILENAME' cmd\n");
            else
                kelfv_print_symbols(ELF_FILE_fp, ELFFileF16Bytes);
        }

        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_CLOSE_FILE_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0){

            if (ELF_FILE_fp){
                fclose(ELF_FILE_fp);
                ELF_FILE_fp = NULL;
                printf("[INFO] File closed\n");
            } else
                printf("[INFO] No file is open\n");
        }


        else if (regexec(&cmdRegexes[KELFV_CMD_REGEX_EXIT_CMD_ENUM],kelfvInputCmd,0,NULL,0) == 0){

            if (ELF_FILE_fp) {
                fclose(ELF_FILE_fp);
                ELF_FILE_fp = NULL;
                printf("[INFO] File closed\n");
            }
            return  1;

        }


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


