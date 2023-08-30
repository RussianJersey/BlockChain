import sys
sys.path.append("blockchain-explorer/")
from blockchainexplorer import *
from wallet import *
from wallet_pool import *

# print(private_key_from_index(10))

print(private_key_from_index(192638791212536871198672312323435643132112412875124687125481247875312768124531))

# pk = "c7d85a0ce87a60e9cb10f1b9ed2c38b4c55cd139ea08c0751a9c481b8bb8cb48"
# for n in range(0,1000) :
#     pk = next_private_key(pk)
#     print(pk)