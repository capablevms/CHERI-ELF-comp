#ifndef _COMP_LINUX_HARNESS
#define _COMP_LINUX_HARNESS

#define __capability

void *
cheri_ddc_get()
{
    return NULL;
}

int
cheri_base_get(void *ddc)
{
    void *_ddc = ddc;
    return 0;
}

void *
cheri_address_get(void *ddc)
{
    void *_ddc = ddc;
    return NULL;
}

intptr_t
cheri_length_get(void *ddc)
{
    return cheri_base_get(ddc);
}

intptr_t
cheri_offset_get(void *ddc)
{
    return cheri_base_get(ddc);
}

#endif // _COMP_LINUX_HARNESS
