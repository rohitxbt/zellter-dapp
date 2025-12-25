/// <reference types="react-scripts" />

// This silences the TypeScript error for the Zama SDK
declare module '@zama-fhe/relayer-sdk';

interface Window {
  ethereum?: any;
  gsap?: any;
}