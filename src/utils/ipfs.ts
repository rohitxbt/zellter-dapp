import axios from 'axios';

// Pinata JWT provided by user
const PINATA_JWT = process.env.REACT_APP_PINATA_JWT;

// Use a dedicated gateway or public one
const IPFS_GATEWAY = "https://gateway.pinata.cloud/ipfs/";

export const uploadToIPFS = async (file: File): Promise<string> => {
  const formData = new FormData();
  formData.append('file', file);

  console.log("Uploading to Pinata...");

  if (!PINATA_JWT) {
      throw new Error("REACT_APP_PINATA_JWT is not defined");
  }

  const res = await axios.post("https://api.pinata.cloud/pinning/pinFileToIPFS", formData, {
      headers: {
          'Authorization': `Bearer ${PINATA_JWT}`
      }
  });

  if (res.data && res.data.IpfsHash) {
      console.log("Pinata Upload Success CID:", res.data.IpfsHash);
      return res.data.IpfsHash;
  } else {
      throw new Error("Pinata upload failed: No CID returned");
  }
};

export const fetchFromIPFS = async (cid: string): Promise<Blob> => {
  console.log("Fetching from IPFS CID:", cid);
  try {
      const res = await axios.get(`${IPFS_GATEWAY}${cid}`, { responseType: 'blob' });
      return res.data;
  } catch (e: any) {
      console.error("Fetch failed from primary gateway", e);
      // Fallback to dweb.link if pinata fails
      const fallbackRes = await axios.get(`https://dweb.link/ipfs/${cid}`, { responseType: 'blob' });
      return fallbackRes.data;
  }
};
