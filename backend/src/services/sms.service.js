import axios from "axios";

export const SMSService = {
  /**
   * Envía un SMS real usando Textbelt
   * @param {string} telefono - Número con lada país (por ejemplo: +521234567890)
   * @param {string} mensaje - Texto del SMS
   */
  async sendSMS(telefono, mensaje) {
    try {
      const response = await axios.post("https://textbelt.com/text", {
        phone: telefono,
        message: mensaje,
        key: "textbelt", // clave gratuita
      });

      if (response.data.success) {
        console.log(`✅ SMS enviado correctamente a ${telefono}`);
      } else {
        console.warn("⚠️ Error en envío:", response.data);
      }

      return response.data;
    } catch (err) {
      console.error("❌ Error al enviar SMS:", err.message);
      throw err;
    }
  },
};
