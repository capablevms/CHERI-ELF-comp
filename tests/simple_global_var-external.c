static int ext_val;

int
get_ext_val(void)
{
    if (!ext_val)
    {
        ext_val = 42;
    }
    return ext_val;
}
