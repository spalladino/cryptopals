module Cryptopals::Attacks::AES

  def self.detect_mode(input : Bytes, ecb_threshold = 0.001, keysize = 16)
    norm_factor = ((input.size / keysize) ** 2).to_f32
    scores = (0...keysize).map do |offset|
      offset_score = 0
      (offset..(input.size-keysize)).step(keysize).each do |i1|
        ((i1+keysize)..(input.size-keysize)).step(keysize).each do |i2|
          offset_score += 1 if input[i1, keysize] == input[i2, keysize]
        end
      end
      offset_score
    end
    score = scores.max.to_f32 / norm_factor
    mode = (score > ecb_threshold) ? Cryptopals::AES::Mode::ECB : Cryptopals::AES::Mode::CBC
    { mode: mode, score: score, scores: scores }
  end

  def self.break_ecb_byte_at_a_time(oracle, keysize = 16)
    totalsize = (0..keysize).map do |offset|
      oracle.call(Bytes.new(offset)).size - offset
    end.max - keysize

    decrypted = Array(UInt8).new
    (0...totalsize).each do |position|
      byte = break_ecb_byte(oracle, decrypted, keysize)
      decrypted.push(byte)
    end
    decrypted.to_slice
  end

  private def self.break_ecb_byte(oracle, decrypted, keysize)
    full_blocks = decrypted.size / keysize
    current_block = decrypted.size % keysize

    target_input = Bytes.new(keysize - 1 - current_block)
    target = oracle.call(target_input)

    (0_u8..255_u8).each do |byte|
      input = [0_u8] * (keysize - 1 - current_block) + decrypted + [byte]
      candidate = oracle.call(input.to_slice)
      return byte if candidate[(full_blocks * keysize), keysize] == target[(full_blocks * keysize), keysize]
    end
    raise "Could not break byte"
  end

  def self.break_cbc_padding_oracle(valid_fun, iv, ciphertext)
    decrypted = Bytes.new(ciphertext.size)
    previous_block = iv
    (0...ciphertext.size).step(16) do |position|
      current_block = ciphertext[position, 16]
      break_cbc_block_padding_oracle(valid_fun, previous_block, current_block, decrypted[position, 16])
      previous_block = current_block
    end
    decrypted.unpad
  end

  private def self.break_cbc_block_padding_oracle(valid_fun, previous_block, current_block, decrypted_block)
    original_block = Bytes.new(16).tap { |bs| bs.copy_from(previous_block) }
    previous_block = Bytes.new(16).tap { |bs| bs.copy_from(previous_block) }

    (1..16).each do |pad_size|
      broken = (1..256).each do |b|
        byte = (b % 256).to_u8
        position = 16 - pad_size
        previous_block[position] = original_block[position] ^ byte

        # orig xor change = pad_size => change = orig xor pad_size
        ((position+1)...16).each { |i| previous_block[i] = original_block[i] ^ (decrypted_block[i] ^ pad_size) }

        if valid_fun.call(previous_block, current_block)
          # orig xor byte = pad_size => orig = pad_size xor byte
          decrypted_block[position] = byte ^ pad_size.to_u8
          break true
        end
        false
      end
      raise "Could not break position #{pad_size}" unless broken
    end
  end

end
