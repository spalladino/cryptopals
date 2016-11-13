require "base64"

struct Char
  def hex_to_byte : UInt8
    if '0' <= self && self <= '9'
      (self - '0').to_u8
    elsif 'a' <= self && self <= 'f'
      (self - 'a' + 10).to_u8
    else
      raise "Invalid hex char: #{self}"
    end
  end
end

class String
  def hex_to_bytes : Bytes
    bytes = Slice(UInt8).new(self.size / 2)
    bytes.size.times do |i|
      bytes[i] = self.char_at(i * 2).hex_to_byte * 16 + self.char_at(i * 2 + 1).hex_to_byte
    end
    bytes
  end
end

class Array(T)
  def to_slice : Slice(T)
    Slice(T).new(Slice(T).new(self.size).copy_from(self.to_unsafe, self.size), self.size)
  end
end

struct Slice(T)
  def to_base64 : String
    Base64.strict_encode(self)
  end
end
