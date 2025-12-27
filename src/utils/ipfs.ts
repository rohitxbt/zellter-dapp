import axios from 'axios';

// Pinata JWT provided by user
const PINATA_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiIwNTRkMDA0Mi1kYjhmLTRlMTYtYWIyMy1jOWIyZjI3MjYyYjMiLCJlbWFpbCI6ImRhZGF0ZWNoNjY2OEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicGluX3BvbGljeSI6eyJyZWdpb25zIjpbeyJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MSwiaWQiOiJGUkExIn0seyJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MSwiaWQiOiJOWUMxIn1dLCJ2ZXJzaW9uIjoxfSwibWZhX2VuYWJsZWQiOmZhbHNlLCJzdGF0dXMiOiJBQ1RJVkUifSwiYXV0aGVudGljYXRpb25UeXBlIjoic2NvcGVkS2V5Iiwic2NvcGVkS2V5S2V5IjoiNDFiNzE5ZTQwN2YzNzk4MmI5NDQiLCJzY29wZWRLZXlTZWNyZXQiOiIxY2U2ZWIwYmJlODIyNjMwYzAwOTAyZWJkMzNjNGFmZDc1M2Q4MzkwNzgxYjE5OTgyNjk0NTAyYjdkMzY4YTE4IiwiZXhwIjoxNzk4MjcxMzY4fQ.TxlDOFM6pHNKb6cESemUFMtxw1aZs1u3VSzE_J6DipI";

// Use a dedicated gateway or public one
const IPFS_GATEWAY = "https://gateway.pinata.cloud/ipfs/";

export const uploadToIPFS = async (file: File): Promise<string> => {
  const formData = new FormData();
  formData.append('file', file);

  console.log("Uploading to Pinata...");

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
