XLEN 8				//表示最大长度为8的字符串
#define MAX_FILES    32			//表示最大文件数量为32
#define MAX_BLOCKSIZE  512		//表示最大块大小为512字节

// 定义每一个目录项的格式
struct dir_entry {
    	char filename[MAXLEN];	//一个字符数组，长度为 MAXLEN，用来存储文件名
    	uint8_t idx;			//用来存储文件的索引
};

// 定义每一个文件的格式。
struct file_blk {
    	uint8_t busy;			//用来标识文件块是否被使用
    	mode_t mode;			//用来表示文件的权限模式
    	uint8_t idx;			//用来存储文件在文件系统中的索引

    	union {					//匿名联合体,包含两个成员变量,但只能使用其中一个成员变量,因为它们共用同一段内存.
        	uint8_t file_size;	//表示文件的大小
        	uint8_t dir_children;	//表示目录的子节点数
    	};
    	char data[0];			//用来存储文件数据
};

// OK，下面的block数组所占据的连续内存就是我的tinyfs的介质，每一个元素代表一个文件。
// struct file_blk block[MAX_FILES+1];
