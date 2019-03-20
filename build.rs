fn main() {
    println!("cargo:rerun-if-changed=\"templates/index.html\"");
    println!("cargo:rerun-if-changed=\"templates/bad_session.html\"");
}