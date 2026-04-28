def fuzzer_result_sort_key(item):
    return (item.command_packet.tar, item.command_packet.keyset)
