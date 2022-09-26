syscall_table
{
    "container":
    {
        "syscall":count
    }
}

fileopen_table
{
    "container":
    {
        [pid,comm,filename,filesystem,time]
    }
}

exec_table
{
    "container":
    {
        [pid,comm,filename,argv,time]
    }
}