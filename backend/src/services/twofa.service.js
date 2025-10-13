import speakeasy from "speakeasy"; 
import bcrypt from "bcryptjs";
import dayjs from "dayjs";

export const TwoFAService = {
  // Genera un código OTP de 6 dígitos (válido 60 segundos)
  generateOTP: () => {
    const otp = speakeasy.totp({
      secret: speakeasy.generateSecret().base32,
      encoding: "base32",
      step: 60,
      digits: 6,
    });
    return otp;
  },

  // Cifra el OTP para guardarlo en BD
  hashOTP: async (otp) => {
    return await bcrypt.hash(otp, 10);
  },

  // Verifica un OTP ingresado contra su hash
  verifyOTP: async (input, hash) => {
    return await bcrypt.compare(input, hash);
  },

  // Valida si el token expiró
  isExpired: (fechaExp) => {
    return dayjs().isAfter(dayjs(fechaExp));
  },
};
