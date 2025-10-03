const ws = new WebSocket("ws://localhost:3001");

const RTP_HEADER_SIZE = 12;

function ulawToLinear(ulawByte) {
  ulawByte = ~ulawByte;
  let sign = ulawByte & 0x80 ? -1 : 1;
  let exponent = (ulawByte >> 4) & 0x07;
  let mantissa = ulawByte & 0x0f;
  let sample = ((mantissa << 1) + 33) << (exponent + 2);
  return sign * (sample - 132);
}

let audioCtx;
let pcmBuffer = [];

document.getElementById("play").onclick = () => {
  if (!audioCtx)
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
};

ws.binaryType = "arraybuffer";

ws.onmessage = (event) => {
  if (!audioCtx) return;
  let data = new Uint8Array(event.data);
  if (data.length <= RTP_HEADER_SIZE) return;

  let pcmuPayload = data.slice(RTP_HEADER_SIZE);

  for (let i = 0; i < pcmuPayload.length; i++) {
    pcmBuffer.push(ulawToLinear(pcmuPayload[i]) / 32768);
  }

  if (pcmBuffer.length >= 800) {
    let buffer = audioCtx.createBuffer(1, pcmBuffer.length, 8000);
    buffer.getChannelData(0).set(pcmBuffer);
    let source = audioCtx.createBufferSource();
    source.buffer = buffer;
    source.connect(audioCtx.destination);
    source.start();
    pcmBuffer = [];
  }
};
