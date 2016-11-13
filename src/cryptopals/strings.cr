module Cryptopals
  FREQUENCIES = Hash(Char, Float32).new
  FREQUENCIES['E'] = 12.02_f32
  FREQUENCIES['T'] = 9.10_f32
  FREQUENCIES['A'] = 8.12_f32
  FREQUENCIES['O'] = 7.68_f32
  FREQUENCIES['I'] = 7.31_f32
  FREQUENCIES['N'] = 6.95_f32
  FREQUENCIES['S'] = 6.28_f32
  FREQUENCIES['R'] = 6.02_f32
  FREQUENCIES['H'] = 5.92_f32
  FREQUENCIES['D'] = 4.32_f32
  FREQUENCIES['L'] = 3.98_f32
  FREQUENCIES['U'] = 2.88_f32
  FREQUENCIES['C'] = 2.71_f32
  FREQUENCIES['M'] = 2.61_f32
  FREQUENCIES['F'] = 2.30_f32
  FREQUENCIES['Y'] = 2.11_f32
  FREQUENCIES['W'] = 2.09_f32
  FREQUENCIES['G'] = 2.03_f32
  FREQUENCIES['P'] = 1.82_f32
  FREQUENCIES['B'] = 1.49_f32
  FREQUENCIES['V'] = 1.11_f32
  FREQUENCIES['K'] = 0.69_f32
  FREQUENCIES['X'] = 0.17_f32
  FREQUENCIES['Q'] = 0.11_f32
  FREQUENCIES['J'] = 0.10_f32
  FREQUENCIES['Z'] = 0.07_f32
end

struct Char
  def freq : Float32
    Cryptopals::FREQUENCIES.fetch(self.upcase, -1_f32) rescue 0_f32
  end
end

class String
  def freqscore : Float32
    self.chars.map(&.freq).sum rescue 0_f32
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
