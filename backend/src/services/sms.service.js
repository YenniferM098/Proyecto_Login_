export const SMSService = {
  sendSMS: async (telefono, mensaje) => {
    // Simulación de envío
    console.log(`📲 Enviando SMS a ${telefono}: ${mensaje}`);

    // En entorno real, puedes usar Twilio o Vonage:
    // import twilio from 'twilio';
    // const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
    // await client.messages.create({
    //   body: mensaje,
    //   from: process.env.TWILIO_PHONE,
    //   to: telefono,
    // });
  },
};
