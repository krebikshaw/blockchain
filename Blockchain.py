import time
import hashlib
import rsa

class Transaction:
  def __init__(self, sender, receiver, amounts, fee, message):
    self.sender = sender
    self.receiver = receiver
    self.amounts = amounts
    self.fee = fee
    self.message = message

class Block:
  def __init__(self, previous_hash, difficulty, miner, miner_rewards):
    self.previous_hash = previous_hash
    self.hash = ''
    self.difficulty = difficulty
    self.nonce = 0
    self.timestamp = int(time.time())
    self.transactions = []
    self.miner = miner
    self.miner_rewards = miner_rewards

class BlockChain:
  def __init__(self):
    self.adjust_difficulty_blocks = 10
    self.difficulty = 5
    self.block_time = 15
    self.miner_rewards = 50
    self.block_limitation = 10
    self.chain = []
    self.pending_transactions = []    

  # 把單一交易明細生成一個字串
  def transaction_to_string(self, transaction):
    transaction_dict = {
      'sender': str(transaction.sender),
      'receiver': str(transaction.receiver),
      'amounts': transaction.amounts,
      'fee': transaction.fee,
      'message': transaction.message
    }
    return str(transaction_dict)

  # 把一個區塊所有交易明細生成一個字串
  def get_transactions_string(self, block):
    transaction_str = ''
    for transaction in block.transactions:
      transaction_str += self.transaction_to_string(transaction)
    return transaction_str

  # 把前一個區塊的 hash 這個區塊的生成時間以及 nonce 生成雜湊值
  def get_hash(self, block, nonce):
    s = hashlib.sha1()
    s.update(
      (
        block.previous_hash
        + str(block.timestamp)
        + self.get_transactions_string(block)
        + str(nonce)
      ).encode("utf-8")
    )
    h = s.hexdigest()
    return h

  # 將等待池中的交易放入區塊
  def add_transaction_to_block(self, block):
    
    # 按照手續費多寡排序
    self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)

    # 依照交易數量是否大於區塊上限，判斷是只收最高的那些，還是全收
    if len(self.pending_transactions) > self.block_limitation:
      transaction_accepted = self.pending_transactions[:self.block_limitaion]
      self.pending_transactions = self.pending_transactions[self.block_limitaion:]
    else:
      transaction_accepted = self.pending_transactions
      self.pending_transactions = []
    block.transactions = transaction_accepted

  # 產生創世塊
  def create_genesis_block(self):
    print("Create genesis block...")
    new_block = Block('Hello World! By Xiang', self.difficulty, 'lkm543', self.miner_rewards)
    new_block.hash = self.get_hash(new_block, 0)
    self.chain.append(new_block)

  # 挖礦
  def mine_block(self, miner):
    start = time.process_time()

    last_block = self.chain[-1]
    new_block = Block(last_block.hash, self.difficulty, miner, self.miner_rewards)

    # 把交易打包入目前區塊
    self.add_transaction_to_block(new_block)
    new_block.previous_hash = last_block.hash
    new_block.difficulty = self.difficulty
    new_block.hash = self.get_hash(new_block, new_block.nonce)

    # 改變 nonce 值直到符合難度
    while new_block.hash[0:self.difficulty] != '0' * self.difficulty:
      new_block.nonce += 1
      new_block.hash = self.get_hash(new_block, new_block.nonce)
    
    time_consumed = round(time.process_time() - start, 5)
    print(f"Hash found: {new_block.hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")
    self.chain.append(new_block)

  # 調節雜湊難度
  def adjust_difficulty(self):

    # 如果還沒到需要驗證的數量，或者現在還在創世塊，無需調整
    if len(self.chain) % self.adjust_difficulty_blocks != 0:
      return self.difficulty
    elif len(self.chain) <= self.adjust_difficulty_blocks:
      return self.difficulty
    else:
      start = self.chain[-1 * self.adjust_difficulty_blocks - 1].timestamp
      finish = self.chain[-1].timestamp
      
      # 用最後一個區塊的 timestamp 與待計算的第一個區塊的 timestamp 相減取平均
      average_time_consumed = round((finish - start) / (self.adjust_difficulty_blocks), 2)
      # 出塊時間過長減少難度，出塊時間過短增加難度
      if average_time_consumed > self.block_time:
        print(f"Average block time: {average_time_consumed}s. Lower the difficulty")
        self.difficulty -= 1
      else:
        print(f"Average block time: {average_time_consumed}s. High up the difficulty")
        self.difficulty += 1

  # 計算帳戶餘額
  def get_balance(self, account):
    balance = 0
    for block in self.chain:
      miner = False

      # 如果該帳號是這個區塊的礦工，加上出塊獎勵
      if block.miner == account:
        miner = True
        balance += block.miner_rewards
      
      # 對照區塊中的每一筆交易，如果這隻帳號是礦工就加上手續費，如果這隻帳號是匯款方就減掉支出，如果這隻帳號是收款方就加上收入
      for transaction in block.transactions:
        if miner:
          balance += transaction.fee
        if transaction.sender == account:
          balance -= transaction.amounts
          balance -= transaction.fee
        elif transaction.receiver == account:
          balance += transaction.amounts
    return balance
  
  # 驗證區塊鏈
  def verify_blockchain(self):
    previous_hash = ''
    for idx, block in enumerate(self.chain):
      
      # 比對每一個區塊的 hash 是否正確
      if self.get_hash(block, block.nonce) != block.hash:
        print("Error: Hash not matched!")
        return False
      elif previous_hash != block.previous_hash and idx:
        print("Error: Hash not matched to previous_hash")
        return False
      previous_hash = block.hash
    
    print("Hash correct!")
    return True

  # 利用 rsa 加密產生一對公私鑰
  def generate_address(self):
    public, private = rsa.newkeys(512)
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()
    return self.get_address_from_public(public_key), \
      self.extract_from_private(private_key)

  # 把公鑰前後不必要的文字濾掉
  def get_address_from_public(self, public):
    address = str(public).replace('\\n','')
    address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
    address = address.replace("-----END RSA PUBLIC KEY-----'", '')
    print('Address:', address)
    return address

  # 把私鑰前後不必要的文字濾掉
  def extract_from_private(self, private):
    private_key = str(private).replace('\\n','')
    private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
    return private_key

  # 礦工驗證交易
  def add_transaction(self, transaction, signature):
    # 透過地址反推公鑰
    public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
    public_key += transaction.sender
    public_key += '\n-----END RSA PUBLIC KEY-----\n'
    public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))

    transaction_str = self.transaction_to_string(transaction)
    # 確認餘額是否足夠
    if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):
      return False, "Balance not enough!"
    # 驗證簽證是否為真
    try:
      rsa.verify(transaction_str.encode('utf-8'), signature, public_key_pkcs)
      self.pending_transactions.append(transaction)
      return True, "Authorized successfully!"
    except Exception:
      return False, "RSA Verified wrong!"

  # 初始化一筆交易
  def initialize_transaction(self, sender, receiver, amount, fee, message):
    if self.get_balance(sender) < amount + fee:
      print("Balance not enough!")
      return False
    new_transaction = Transaction(sender, receiver, amount, fee, message)
    return new_transaction

  # 利用私鑰簽署交易
  def sign_transaction(self, transaction, private):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private 
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    transaction_str = self.transaction_to_string(transaction)
    signature = rsa.sign(transaction_str.encode('utf-8'), private_key_pkcs, 'SHA-1')
    return signature

  # 測試執行
  def start(self):
    address, private = self.generate_address()
    self.create_genesis_block()
    while(True):
      # 初始化一筆交易
      transaction = self.initialize_transaction(address, 'test123', 1, 1, 'Test')
      if transaction:
        # 將交易透過私鑰進行簽證
        signature = self.sign_transaction(transaction, private)
        # 礦工進行驗證
        self.add_transaction(transaction, signature)
      self.mine_block(address)
      print(self.get_balance(address))
      self.adjust_difficulty()

if __name__ == '__main__':
  block = BlockChain()
  block.start()

  # block.create_genesis_block()
  # block.mine_block('lkm543')
  # block.verify_blockchain()

  # print("insert fake transaction.")
  # fake_transaction = Transaction('test123', 'address', 100, 1, 'Test')
  # block.chain[1].transactions.append(fake_transaction)
  # block.mine_block('lkm543')
  # block.verify_blockchain()
