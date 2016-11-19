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

end
