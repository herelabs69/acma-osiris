import { CctvCamera } from './types';

export async function fetchSwitzerlandCameras(): Promise<CctvCamera[]> {
  return [
    {
      id: 'chuv-heliport',
      lat: 46.5250,
      lng: 6.6420,
      name: 'CHUV Heliport Webcam',
      city: 'Lausanne',
      country: 'Switzerland',
      stream_type: 'jpg',
      stream_url: 'https://wc-heli.chuv.ch/axis-cgi/jpg/image.cgi?resolution=640x480',
      external_url: 'https://wc-heli.chuv.ch/view/view.shtml',
      source: 'chuv.ch'
    }
  ];
}
