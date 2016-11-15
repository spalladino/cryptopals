module Cryptopals
  FREQUENCIES = Hash(Char, Float32).new
  FREQUENCIES['E'] = 0.1202_f32
  FREQUENCIES['T'] = 0.0910_f32
  FREQUENCIES['A'] = 0.0812_f32
  FREQUENCIES['O'] = 0.0768_f32
  FREQUENCIES['I'] = 0.0731_f32
  FREQUENCIES['N'] = 0.0695_f32
  FREQUENCIES['S'] = 0.0628_f32
  FREQUENCIES['R'] = 0.0602_f32
  FREQUENCIES['H'] = 0.0592_f32
  FREQUENCIES['D'] = 0.0432_f32
  FREQUENCIES['L'] = 0.0398_f32
  FREQUENCIES['U'] = 0.0288_f32
  FREQUENCIES['C'] = 0.0271_f32
  FREQUENCIES['M'] = 0.0261_f32
  FREQUENCIES['F'] = 0.0230_f32
  FREQUENCIES['Y'] = 0.0211_f32
  FREQUENCIES['W'] = 0.0209_f32
  FREQUENCIES['G'] = 0.0203_f32
  FREQUENCIES['P'] = 0.0182_f32
  FREQUENCIES['B'] = 0.0149_f32
  FREQUENCIES['V'] = 0.0111_f32
  FREQUENCIES['K'] = 0.0069_f32
  FREQUENCIES['X'] = 0.0017_f32
  FREQUENCIES['Q'] = 0.0011_f32
  FREQUENCIES['J'] = 0.0010_f32
  FREQUENCIES['Z'] = 0.0007_f32
end

struct Char
  def freq : Float32
    Cryptopals::FREQUENCIES.fetch(self.upcase, 0_f32) rescue 0_f32
  end
end

class String
  def freqscore : Float32
    begin
      freqs = Hash(Char, Int32).new(0)
      return Float32::MAX if self.chars.any?{|c| c.control? && c != '\n'}
      self.chars.each { |c| freqs[c.upcase] += 1 }
    rescue
      return Float32::MAX
    end

    Cryptopals::FREQUENCIES.map do |char, expected_freq|
      actual_freq = freqs[char].to_f32 / self.size
      (expected_freq - actual_freq) ** 2
    end.sum
  end

  def hamming_distance(other : String) : Int32
    self.to_slice.hamming_distance(other.to_slice)
  end
end

struct Slice(T)
  def hamming_distance(other : Bytes) : Int32
    self.xor(other).map(&.popcount.to_i32).sum
  end
end
