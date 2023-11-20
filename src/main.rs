#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use openssl::{md::Md, md_ctx::MdCtx};

type Digest = [u8; 32];

#[inline]
fn byte_validate(digest: &Digest) -> bool {
    for block in digest.windows(5) {
        assert!(block.len() == 5);
        if block[0] != b'\'' {
            continue;
        }
        if !(block[1] == b'|' && block[2] == b'|' || block[1] == b'o' && block[2] == b'r') {
            continue;
        }
        if block[3] != b'\'' {
            continue;
        }
        if block[4] < b'0' || block[4] > b'9' {
            continue;
        }
        return true;
    }
    false
}

// 87153179503375488964249572016766023268706569805029887102402011499288342510775092757977654940386142689199562616975803271832089582121260280598138107679172885818920928633840231384484533108096150415512236913966

fn main() {
    let start_time = std::time::Instant::now();
    crack();
    let end_time = std::time::Instant::now();
    println!("Time taken: {:?}", end_time - start_time);
}

fn crack() {
    // Create all in memory objects here to reduce re-allocation.
    let mut i = 0;
    let mut buf = Vec::with_capacity(400);
    let mut digest: Digest = [0; 32];
    let mut ctx = MdCtx::new().unwrap();
    // Distribution for selecting random
    loop {
        if i % 1_000_000 == 0 {
            println!("i = {i}");
        }

        #[cfg(feature = "perf")]
        if i > 10_000_000 {
            return;
        }

        if i & 100 == 0 {
            buf.clear();
        }

        i += 1;

        // Push new byte to buf
        // Ascii codes for digits.
        let next_ascii_char: u8 = fastrand::u8(48..=57);
        buf.push(next_ascii_char);

        // Calculate md5 hash
        // let str_digest = openssl_str_digest(&buf, &mut digest);
        openssl_digest(&mut ctx, unsafe { std::str::from_utf8_unchecked(&buf) }, &mut digest);

        // Check if we can create the OR statement from it.
        if byte_validate(&digest) {
            println!("Found! i = {i}");
            println!("Content = {buf}", buf = unsafe { std::str::from_utf8_unchecked(&buf) });
            let str_digest = String::from_utf8_lossy(&digest);
            println!("Raw md5 Hash = {str_digest}");
            return;
        }
    }
}

#[inline]
fn openssl_digest(ctx: &mut MdCtx, buf: &str, digest: &mut [u8; 32]) {
    unsafe {
        ctx.digest_init(Md::md5()).unwrap_unchecked();
        ctx.digest_update(buf.as_bytes()).unwrap_unchecked();
        ctx.digest_final(digest).unwrap_unchecked();
    }
}

#[test]
fn test_validation() {
    let buf = "129581926211651571912466741651878684928";

    let mut digest = [0; 32];
    let mut ctx = MdCtx::new().unwrap();

    openssl_digest(&mut ctx, buf, &mut digest);

    let str_digest = String::from_utf8_lossy(&digest);
    println!("{str_digest}");
    assert!(byte_validate(&digest));
}
