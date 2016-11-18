module Cryptopals::Attacks::AES

  def self.detect_mode(input : Bytes, ecb_threshold = 0.001)
    norm_factor = ((input.size / 16) ** 2).to_f32
    scores = (0...16).map do |offset|
      offset_score = 0
      (offset..(input.size-16)).step(16).each do |i1|
        ((i1+16)..(input.size-16)).step(16).each do |i2|
          offset_score += 1 if input[i1, 16] == input[i2, 16]
        end
      end
      offset_score
    end
    score = scores.max.to_f32 / norm_factor
    mode = (score > ecb_threshold) ? Cryptopals::AES::Mode::ECB : Cryptopals::AES::Mode::CBC
    { mode: mode, score: score, scores: scores }
  end

end
